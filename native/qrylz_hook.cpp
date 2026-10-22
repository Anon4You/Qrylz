// Qrylz native hook.
//
// The runtime half of Qrylz. A signature check that reads the certificate out of the APK
// file - in native code - is not reachable from Java. This library intercepts the file
// opens of the host application and serves a copy of the original APK instead, so such
// a check finds the original certificate.
//
// The interception is done on the PLT of every loaded module: the stub of a relocation
// is replaced with a jump to our function, the GOT entry is left alone so the original
// address can still be read from it.

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "QrylzHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1027
#endif
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif

static char g_apk_path[PATH_MAX];
static char g_origin_path[PATH_MAX];
static volatile int g_ready = 0;

// GOT slots of the hooked functions, used to call the original ones.
static void *g_got_open = NULL;
static void *g_got_open64 = NULL;
static void *g_got_openat = NULL;
static void *g_got_openat64 = NULL;
static void *g_got_fopen = NULL;
static void *g_got_fopen64 = NULL;

static pthread_t g_scanner;
static volatile int g_stop = 0;

static int serves(const char *path) {
    if (!g_ready || path == NULL) {
        return 0;
    }
    return strcmp(path, g_apk_path) == 0;
}

// The original functions, read from the GOT entries.
static int (*orig_open)(const char *, int, ...) = NULL;
static int (*orig_open64)(const char *, int, ...) = NULL;
static int (*orig_openat)(int, const char *, int, ...) = NULL;
static int (*orig_openat64)(int, const char *, int, ...) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *(*orig_fopen64)(const char *, const char *) = NULL;

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

// ---------------------------------------------------------------------------
// ELF handling
// ---------------------------------------------------------------------------

struct Segment {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t size;
};

// Reads the file into memory and returns its base address, or NULL.
static unsigned char *read_file(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return NULL;
    }
    size_t size = (size_t) st.st_size;
    unsigned char *data = (unsigned char *) malloc(size);
    if (data == NULL) {
        close(fd);
        return NULL;
    }
    ssize_t total = 0;
    while ((size_t) total < size) {
        ssize_t n = read(fd, data + total, size - (size_t) total);
        if (n <= 0) {
            break;
        }
        total += n;
    }
    close(fd);
    if ((size_t) total != size) {
        free(data);
        return NULL;
    }
    *out_size = size;
    return data;
}

static uint64_t vaddr_to_offset(const struct Segment *segments, int count, uint64_t vaddr) {
    for (int i = 0; i < count; i++) {
        if (vaddr >= segments[i].vaddr && vaddr < segments[i].vaddr + segments[i].size) {
            return segments[i].offset + (vaddr - segments[i].vaddr);
        }
    }
    return (uint64_t) -1;
}

// Decodes the aarch64 adrp/ldr pair of a PLT stub and returns the GOT address it
// refers to, or 0 when the stub does not look like one.
static uint64_t stub_got(const unsigned char *stub) {
    uint32_t adrp = *(const uint32_t *) stub;
    uint32_t ldr = *(const uint32_t *) (stub + 4);
    if ((adrp & 0x9F000000u) != 0x90000000u) {
        return 0;
    }
    if ((ldr & 0xFFC00000u) != 0xF9400000u) {
        return 0;
    }
    uint64_t immhi = (adrp >> 5) & 0x7FFFF;
    uint64_t immlo = (adrp >> 29) & 0x3;
    int64_t page = (int64_t) ((immhi << 2) | immlo);
    page <<= 12;
    uint64_t pc = (uint64_t) (uintptr_t) stub & ~0xFFFull;
    uint64_t reg = (uint64_t) (int64_t) (pc + page);
    uint64_t offset = ((ldr >> 10) & 0xFFF) * 8u;
    return reg + offset;
}

// Replaces a PLT stub with a jump to the given function.
static int patch_stub(uint64_t stub_address, void *target) {
    uint32_t code[4];
    // ldr x16, #8
    code[0] = 0x58000050u;
    // br x16
    code[1] = 0xD61F0200u;
    uint64_t address = (uint64_t) (uintptr_t) target;
    memcpy(&code[2], &address, sizeof(address));

    long page = (long) (stub_address & ~0xFFFull);
    if (mprotect((void *) page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }
    memcpy((void *) stub_address, code, sizeof(code));
    __builtin___clear_cache((char *) stub_address, (char *) (stub_address + sizeof(code)));
    return 0;
}

struct Target {
    const char *name;
    void **got;
    void *hook;
};

static int hook_module(const char *path) {
    size_t size = 0;
    unsigned char *data = read_file(path, &size);
    if (data == NULL) {
        return -1;
    }
    if (size < sizeof(Elf64_Ehdr) || memcmp(data, ELFMAG, SELFMAG) != 0) {
        free(data);
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) data;
    if (ehdr->e_machine != EM_AARCH64) {
        free(data);
        return -1;
    }

    struct Segment segments[16];
    int segment_count = 0;
    for (int i = 0; i < ehdr->e_phnum && segment_count < 16; i++) {
        Elf64_Phdr *phdr = (Elf64_Phdr *) (data + ehdr->e_phoff + i * sizeof(Elf64_Phdr));
        if (phdr->p_type == PT_LOAD) {
            segments[segment_count].vaddr = phdr->p_vaddr;
            segments[segment_count].offset = phdr->p_offset;
            segments[segment_count].size = phdr->p_filesz;
            segment_count++;
        }
    }
    if (segment_count == 0) {
        free(data);
        return -1;
    }

    // The dynamic section carries the symbol and relocation tables.
    Elf64_Dyn *dynamic = NULL;
    uint64_t dynamic_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = (Elf64_Phdr *) (data + ehdr->e_phoff + i * sizeof(Elf64_Phdr));
        if (phdr->p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *) (data + phdr->p_offset);
            dynamic_size = phdr->p_filesz;
            break;
        }
    }
    if (dynamic == NULL) {
        free(data);
        return -1;
    }

    uint64_t symtab = 0, strtab = 0, strsz = 0;
    uint64_t jmprel = 0, jmprelsz = 0, pltrel = 0, rela = 0, relasz = 0, relent = 0;
    for (uint64_t off = 0; off + sizeof(Elf64_Dyn) <= dynamic_size; off += sizeof(Elf64_Dyn)) {
        Elf64_Dyn *dyn = &dynamic[off / sizeof(Elf64_Dyn)];
        if (dyn->d_tag == DT_NULL) {
            break;
        }
        switch (dyn->d_tag) {
            case DT_SYMTAB: symtab = dyn->d_un.d_ptr; break;
            case DT_STRTAB: strtab = dyn->d_un.d_ptr; break;
            case DT_STRSZ: strsz = dyn->d_un.d_val; break;
            case DT_JMPREL: jmprel = dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprelsz = dyn->d_un.d_val; break;
            case DT_PLTREL: pltrel = dyn->d_un.d_val; break;
            case DT_RELA: rela = dyn->d_un.d_ptr; break;
            case DT_RELASZ: relasz = dyn->d_un.d_val; break;
            case DT_RELAENT: relent = dyn->d_un.d_val; break;
            default: break;
        }
    }
    if (symtab == 0 || strtab == 0) {
        free(data);
        return -1;
    }

    // The PLT section holds the stubs.
    uint64_t plt_address = 0, plt_size = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = (Elf64_Shdr *) (data + ehdr->e_shoff + i * sizeof(Elf64_Shdr));
        if (shdr->sh_type == SHT_PROGBITS && shdr->sh_flags & SHF_ALLOC
                && shdr->sh_size > 0 && (shdr->sh_flags & SHF_EXECINSTR)) {
            // The executable section that holds the stubs is the one right before the
            // relocations are applied to; the dynamic symbol table lives in a
            // non executable section, so the stub section is found by looking for the
            // section that starts with the plt header.
            if (plt_address == 0 && shdr->sh_addr != 0) {
                plt_address = shdr->sh_addr;
                plt_size = shdr->sh_size;
            }
        }
    }
    if (plt_address == 0) {
        free(data);
        return -1;
    }
    uint64_t plt_offset = vaddr_to_offset(segments, segment_count, plt_address);
    if (plt_offset == (uint64_t) -1) {
        free(data);
        return -1;
    }

    struct Target targets[] = {
            {"open", &g_got_open, (void *) hooked_open},
            {"open64", &g_got_open64, (void *) hooked_open64},
            {"openat", &g_got_openat, (void *) hooked_openat},
            {"openat64", &g_got_openat64, (void *) hooked_openat64},
            {"fopen", &g_got_fopen, (void *) hooked_fopen},
            {"fopen64", &g_got_fopen64, (void *) hooked_fopen64},
    };

    int patched = 0;
    // Walk the jump slot relocations and the global ones, both can hold the address of
    // a libc function.
    for (int pass = 0; pass < 2; pass++) {
        uint64_t rel_address = pass == 0 ? jmprel : rela;
        uint64_t rel_size = pass == 0 ? jmprelsz : relasz;
        uint64_t rel_entry = pass == 0 ? (pltrel == DT_RELA ? sizeof(Elf64_Rela) : 0) : relent;
        if (rel_address == 0 || rel_size == 0 || rel_entry == 0) {
            continue;
        }
        uint64_t rel_offset = vaddr_to_offset(segments, segment_count, rel_address);
        if (rel_offset == (uint64_t) -1) {
            continue;
        }
        for (uint64_t off = 0; off + rel_entry <= rel_size; off += rel_entry) {
            Elf64_Rela *rela = (Elf64_Rela *) (data + rel_offset + off);
            uint32_t type = (uint32_t) (rela->r_info & 0xFFFFFFFFu);
            if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) {
                continue;
            }
            uint32_t symbol = (uint32_t) (rela->r_info >> 32);
            if (symbol == 0) {
                continue;
            }
            uint64_t sym_offset = vaddr_to_offset(segments, segment_count, symtab + symbol * sizeof(Elf64_Sym));
            if (sym_offset == (uint64_t) -1) {
                continue;
            }
            Elf64_Sym *sym = (Elf64_Sym *) (data + sym_offset);
            if (sym->st_name == 0 || sym->st_name >= strsz) {
                continue;
            }
            uint64_t name_offset = vaddr_to_offset(segments, segment_count, strtab + sym->st_name);
            if (name_offset == (uint64_t) -1) {
                continue;
            }
            const char *name = (const char *) (data + name_offset);

            for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
                if (strcmp(name, targets[t].name) != 0) {
                    continue;
                }
                // The GOT entry holds the address of the original function.
                uint64_t got_address = rela->r_offset;
                if (*targets[t].got != NULL) {
                    continue;
                }
                // Find the stub that refers to this GOT entry.
                for (uint64_t stub = 0; stub + 16 <= plt_size; stub += 16) {
                    uint64_t stub_address = plt_address + stub;
                    uint64_t stub_offset = plt_offset + stub;
                    if (stub_offset + 16 > size) {
                        break;
                    }
                    if (stub_got(data + stub_offset) != got_address) {
                        continue;
                    }
                    if (patch_stub(stub_address, targets[t].hook) == 0) {
                        *(targets[t].got) = (void *) got_address;
                        // The GOT entry still holds the address of the original.
                        void **slot = (void **) got_address;
                        void *original = *slot;
                        if (original == NULL) {
                            original = dlsym(RTLD_NEXT, targets[t].name);
                        }
                        if (t == 0) orig_open = (int (*)(const char *, int, ...)) original;
                        if (t == 1) orig_open64 = (int (*)(const char *, int, ...)) original;
                        if (t == 2) orig_openat = (int (*)(int, const char *, int, ...)) original;
                        if (t == 3) orig_openat64 = (int (*)(int, const char *, int, ...)) original;
                        if (t == 4) orig_fopen = (FILE * (*)(const char *, const char *)) original;
                        if (t == 5) orig_fopen64 = (FILE * (*)(const char *, const char *)) original;
                        patched++;
                        LOGI("hooked %s in %s", name, path);
                    }
                    break;
                }
            }
        }
    }

    free(data);
    return patched;
}

// Hooks every module that is currently mapped.
static void hook_all_modules() {
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == NULL) {
        return;
    }
    char line[4096];
    char last[PATH_MAX] = {0};
    while (fgets(line, sizeof(line), maps) != NULL) {
        char *path = strchr(line, '/');
        if (path == NULL) {
            continue;
        }
        path[strcspn(path, "\n")] = 0;
        if (strcmp(path, last) == 0) {
            continue;
        }
        snprintf(last, sizeof(last), "%s", path);
        if (strstr(path, "/dev/") != NULL || strstr(path, "[") != NULL) {
            continue;
        }
        hook_module(path);
    }
    fclose(maps);
}

static void *scanner_thread(void *arg) {
    (void) arg;
    while (!g_stop) {
        hook_all_modules();
        for (int i = 0; i < 10 && !g_stop; i++) {
            usleep(100000);
        }
    }
    return NULL;
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

    hook_all_modules();
    g_ready = 1;

    if (pthread_create(&g_scanner, NULL, scanner_thread, NULL) == 0) {
        pthread_detach(g_scanner);
    }
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
