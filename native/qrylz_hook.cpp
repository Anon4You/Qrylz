// Qrylz native hook.
//
// The runtime half of the native level bypass. A signature check that reads the
// certificate out of the apk file opens the apk through the libc, so the opens of the
// apk of the host application are redirected to a copy of the original apk.
//
// The calls of an application go through the plt of its shared libraries, and every
// plt stub jumps through an entry of the global offset table. The relocation that
// belongs to the stub says where that entry is, so the entry can be pointed at our
// own function. That is the same on every architecture, only the elf class and the
// shape of the relocation differ.
//
// The path of the apk is found in the memory maps of the process, which is where the
// native code of an application looks for it as well.

#include <jni.h>
#include <android/dlext.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "QrylzHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static char g_apk_path[PATH_MAX];
static char g_origin_path[PATH_MAX];
static volatile int g_ready = 0;

// The originals, resolved through dlsym before any table is patched. Reading them out
// of a table entry is not safe: an entry that has not been resolved yet points at the
// lazy binding stub of that module, and patching the same entry would make the stub
// jump back into the hook.
static int (*orig_open)(const char *, int, ...) = NULL;
static int (*orig_open64)(const char *, int, ...) = NULL;
static int (*orig_openat)(int, const char *, int, ...) = NULL;
static int (*orig_openat64)(int, const char *, int, ...) = NULL;
static int (*orig_open_2)(const char *, int) = NULL;
static int (*orig_openat_2)(int, const char *, int) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *(*orig_fopen64)(const char *, const char *) = NULL;
static void *(*orig_dlopen)(const char *, int) = NULL;
static void *(*orig_android_dlopen_ext)(const char *, int, const android_dlextinfo *) = NULL;

// One function that is redirected.
struct Target {
    const char *symbol;
    void *hook;
    void **original;
};

static void patch_all();

// The modules loaded at startup and the modules loaded later are patched the same way.
static pthread_mutex_t g_patch_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @return true when the path is the apk of the host application
 */
static int serves(const char *path) {
    if (!g_ready || path == NULL) {
        return 0;
    }
    return strcmp(path, g_apk_path) == 0;
}

static int hooked_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }
    if (serves(path)) {
        return orig_open(g_origin_path, flags, mode);
    }
    return orig_open(path, flags, mode);
}

static int hooked_open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }
    if (serves(path)) {
        return orig_open64(g_origin_path, flags, mode);
    }
    return orig_open64(path, flags, mode);
}

static int hooked_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }
    if (serves(path)) {
        return orig_openat(dirfd, g_origin_path, flags, mode);
    }
    return orig_openat(dirfd, path, flags, mode);
}

static int hooked_openat64(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }
    if (serves(path)) {
        return orig_openat64(dirfd, g_origin_path, flags, mode);
    }
    return orig_openat64(dirfd, path, flags, mode);
}

static FILE *hooked_fopen(const char *path, const char *mode) {
    if (serves(path)) {
        return orig_fopen(g_origin_path, mode);
    }
    return orig_fopen(path, mode);
}

static FILE *hooked_fopen64(const char *path, const char *mode) {
    if (serves(path)) {
        return orig_fopen64(g_origin_path, mode);
    }
    return orig_fopen64(path, mode);
}

// NDK release builds compile a two argument open/openat into the FORTIFY variants.
static int hooked_open_2(const char *path, int flags) {
    if (serves(path)) {
        return orig_open_2(g_origin_path, flags);
    }
    return orig_open_2(path, flags);
}

static int hooked_openat_2(int dirfd, const char *path, int flags) {
    if (serves(path)) {
        return orig_openat_2(dirfd, g_origin_path, flags);
    }
    return orig_openat_2(dirfd, path, flags);
}

// A library that is loaded after the first patch has its own fresh table. Patch every
// module again after the load returns, before the caller runs JNI_OnLoad. The library's
// ELF constructors have already run inside dlopen, so they are not covered.
static void *hooked_dlopen(const char *filename, int flag) {
    void *handle = orig_dlopen(filename, flag);
    patch_all();
    return handle;
}

static void *hooked_android_dlopen_ext(const char *filename, int flag,
                                       const android_dlextinfo *info) {
    void *handle = orig_android_dlopen_ext(filename, flag, info);
    patch_all();
    return handle;
}

static Target g_targets[] = {
        {"openat64", (void *) hooked_openat64, (void **) &orig_openat64},
        {"openat", (void *) hooked_openat, (void **) &orig_openat},
        {"open64", (void *) hooked_open64, (void **) &orig_open64},
        {"open", (void *) hooked_open, (void **) &orig_open},
        {"__openat_2", (void *) hooked_openat_2, (void **) &orig_openat_2},
        {"__open_2", (void *) hooked_open_2, (void **) &orig_open_2},
        {"fopen64", (void *) hooked_fopen64, (void **) &orig_fopen64},
        {"fopen", (void *) hooked_fopen, (void **) &orig_fopen},
        {"android_dlopen_ext", (void *) hooked_android_dlopen_ext,
         (void **) &orig_android_dlopen_ext},
        {"dlopen", (void *) hooked_dlopen, (void **) &orig_dlopen},
};

static const int g_target_count = (int) (sizeof(g_targets) / sizeof(g_targets[0]));

/**
 * Resolves every original through the default symbol scope. A slot is only patched when
 * the original is known, so a hook can never call itself.
 */
static void resolve_originals() {
    for (int i = 0; i < g_target_count; i++) {
        if (*g_targets[i].original == NULL) {
            *g_targets[i].original = dlsym(RTLD_DEFAULT, g_targets[i].symbol);
        }
        if (*g_targets[i].original == NULL) {
            LOGW("cannot resolve %s", g_targets[i].symbol);
        }
    }
}

// ------------------------------------------------------------------ the patching

/**
 * Points the global offset table entries of the plt relocations of a module at the
 * given functions.
 *
 * The elf structures are the ones of the platform, they are 32 bit on a 32 bit build and
 * 64 bit on a 64 bit one. A process only ever loads modules of its own class, so one
 * implementation covers all of them.
 */
static void patch_module(uintptr_t base, const ElfW(Phdr) *phdrs, int phnum,
                         const Target *targets, int count) {
    const ElfW(Dyn) *dynamic = NULL;
    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dynamic = (const ElfW(Dyn) *) (base + phdrs[i].p_vaddr);
            break;
        }
    }
    if (dynamic == NULL) {
        return;
    }

    uintptr_t symtab = 0, strtab = 0, jmprel = 0;
    size_t jmprelsz = 0, strsz = 0;
    int pltrel = 0;
    for (const ElfW(Dyn) *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB: symtab = (uintptr_t) (base + dyn->d_un.d_ptr); break;
            case DT_STRTAB: strtab = (uintptr_t) (base + dyn->d_un.d_ptr); break;
            case DT_STRSZ: strsz = dyn->d_un.d_val; break;
            case DT_JMPREL: jmprel = (uintptr_t) (base + dyn->d_un.d_ptr); break;
            case DT_PLTRELSZ: jmprelsz = dyn->d_un.d_val; break;
            case DT_PLTREL: pltrel = dyn->d_un.d_val; break;
            default: break;
        }
    }
    if (symtab == 0 || strtab == 0 || jmprel == 0 || jmprelsz == 0) {
        return;
    }

    const bool uses_rela = (pltrel == DT_RELA);
    const size_t entry_size = uses_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return;
    }

    for (size_t offset = 0; offset + entry_size <= jmprelsz; offset += entry_size) {
        uintptr_t r_offset;
        // The info field is 64 bit wide on a 64 bit elf, the symbol index lives in its
        // upper half. Truncating it to 32 bit loses the index and no relocation matches.
        uint64_t r_info;
        if (uses_rela) {
            const ElfW(Rela) *rela = (const ElfW(Rela) *) (jmprel + offset);
            r_offset = (uintptr_t) rela->r_offset;
            r_info = (uint64_t) rela->r_info;
        } else {
            const ElfW(Rel) *rel = (const ElfW(Rel) *) (jmprel + offset);
            r_offset = (uintptr_t) rel->r_offset;
            r_info = (uint64_t) rel->r_info;
        }

        // The symbol index sits in the upper half of the info field on 64 bit and above
        // the low half on 32 bit.
        uint32_t symbol = sizeof(ElfW(Addr)) == 8 ? (uint32_t) (r_info >> 32)
                                                  : (uint32_t) (r_info >> 8);
        if (symbol == 0) {
            continue;
        }
        const ElfW(Sym) *sym = (const ElfW(Sym) *) (symtab + symbol * sizeof(ElfW(Sym)));
        if (sym->st_name == 0 || sym->st_name >= strsz) {
            continue;
        }
        const char *name = (const char *) (strtab + sym->st_name);

        for (int i = 0; i < count; i++) {
            if (strcmp(name, targets[i].symbol) != 0) {
                continue;
            }
            // Never install a hook whose original is unknown, it would call itself.
            if (*targets[i].original == NULL) {
                break;
            }
            uintptr_t slot = base + r_offset;
            // The entry of the table is read only when the module was linked with full
            // relocation protection, so the page has to be made writable first.
            long page = (long) (slot & ~((uintptr_t) page_size - 1));
            if (mprotect((void *) page, (size_t) page_size, PROT_READ | PROT_WRITE) != 0) {
                LOGW("cannot make the table writable in %s", name);
                break;
            }
            *(void **) slot = targets[i].hook;
            // The page stays writable. A module linked without BIND_NOW resolves other
            // entries of the same page lazily, and the linker has to write them.
            break;
        }
    }
}

static int patch_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size;
    (void) data;
    const Target *targets = (const Target *) data;
    if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0') {
        // The main executable is not a shared library, its calls do not go through a
        // plt of a library.
        return 0;
    }
    if (strstr(info->dlpi_name, ".so") == NULL) {
        return 0;
    }
    uintptr_t base = (uintptr_t) info->dlpi_addr;
    patch_module(base, info->dlpi_phdr, info->dlpi_phnum, targets, g_target_count);
    return 0;
}

/**
 * Patches the modules that are loaded right now. Called once at startup and again after
 * every library load, so a module loaded after the payload starts is covered too.
 */
static void patch_all() {
    pthread_mutex_lock(&g_patch_mutex);
    dl_iterate_phdr(patch_callback, g_targets);
    pthread_mutex_unlock(&g_patch_mutex);
}

extern "C" JNIEXPORT void JNICALL
Java_alienkrishn_qrylz_payload_QrylzNative_nativeInit(JNIEnv *env, jclass clazz,
                                                      jstring apk_path, jstring origin_path) {
    (void) clazz;
    if (apk_path == NULL || origin_path == NULL) {
        return;
    }
    const char *apk = env->GetStringUTFChars(apk_path, NULL);
    const char *origin = env->GetStringUTFChars(origin_path, NULL);
    snprintf(g_apk_path, sizeof(g_apk_path), "%s", apk);
    snprintf(g_origin_path, sizeof(g_origin_path), "%s", origin);
    env->ReleaseStringUTFChars(apk_path, apk);
    env->ReleaseStringUTFChars(origin_path, origin);

    resolve_originals();
    patch_all();

    g_ready = 1;
    LOGI("serving %s for %s", g_origin_path, g_apk_path);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
