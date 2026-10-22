# Qrylz

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java 17](https://img.shields.io/badge/java-17-blue.svg)](https://openjdk.org/)
[![Gradle](https://img.shields.io/badge/gradle-9-green.svg)](https://gradle.org/)

Patch an Android APK so that **signature verification keeps working after the APK has been
re-signed** - without the apk growing by the size of a second copy of itself.

Qrylz is a command line tool. It merges split apks, reads the original signing
certificate, injects a small payload and writes the patched apk out. The result is
**not signed**, sign it with your own key afterwards.

```
 original.apk  73.8 MB
 patched.apk   74.4 MB   (+617 KB)
```

## Installation

From the [TermuxVoid repository](https://termuxvoid.github.io):

```bash
pkg install qrylz
```

---

## What it does

An application that checks its own signature has to be able to find a certificate. There
are two places it can look, and both have to keep working after the apk was signed with a
different key:

| Where the check happens | What Qrylz does |
| --- | --- |
| the application asks the package manager for its own signature | the parcel creator of `PackageInfo` is replaced, so every package info that is unmarshalled reports the original certificate |
| the application reads the certificate out of the apk file, usually from native code | the opens of the apk are redirected to a copy of the original apk |
| the application has to start at all | `android:appComponentFactory` points at the payload, so it runs before the application class is loaded |

The original apk is kept **byte for byte** as the prefix of the patched apk:

```
 patched.apk
 +----------------------------------------------------------------+
 |  the original apk, unchanged  |  AndroidManifest.xml   <- patched  |
 |  (the payload serves this)    |  classes5.dex          <- payload  |
 |                               |  lib/arm64-v8a/...so   <- the hook  |
 +----------------------------------------------------------------+
 |  central directory, end record                                  |
 +----------------------------------------------------------------+
```

Because those bytes are already in the file, the patched apk only grows by the entries
that were added and by one more central directory.

---

## Usage

```bash
java -jar qrylz.jar -i app.apk -o patched.apk
```

The jar is self contained, the native hook is bundled in it.

```
Usage: qrylz [-hV] -i=<apk> -o=<apk> [--payload=<dex>] [--lib=<so>]

  -i, --input=<apk>    Input APK or split APK set (.apk, .apks, .xapk, .apkm)
  -o, --output=<apk>   Output APK (not signed)
      --payload=<dex>  Payload dex to inject. Defaults to the bundled payload.dex.
      --lib=<so>       Native hook to inject as lib/arm64-v8a/libqrylz_hook.so.
                       Defaults to the one bundled in this jar.
  -h, --help           Show this help message and exit.
  -V, --version        Print version information and exit.
```

### Signing

The tool does not sign, so that it does not have to carry a signing library. Sign the
result with your own key:

```bash
apksigner sign --ks my.jks --out signed.apk patched.apk
```

Do **not** run `zipalign` over the result. It cannot relocate the apk signature block,
and that block is what the payload serves to the application. The entries Qrylz adds are
aligned on their own.

---

## Build

```bash
./gradlew shadowJar
```

The fat jar lands in `build/libs/qrylz.jar` and is about 2.7 MB. It contains the payload
dex and the native hook for every abi, so one download is enough.

Two things are needed besides a JDK 17:

* the **Android SDK**, for `d8`, which turns the payload into `payload.dex`
* the **Android NDK**, for the native hook

```properties
# local.properties
sdk.dir=/path/to/android-sdk
```

The native hook is built by the build itself, `./gradlew buildNativeHook` does it on its
own, one build directory per abi.

---

## How it works

### The java level

Every `PackageInfo` that comes back from the package manager is unmarshalled through
`PackageInfo.CREATOR`. Replacing that creator with one that swaps the certificate is
enough to cover every caller - the package manager can be asked in many different ways
and all of them end up in the same creator.

```java
Parcelable.Creator<PackageInfo> creator = new Parcelable.Creator<PackageInfo>() {
    public PackageInfo createFromParcel(Parcel source) {
        PackageInfo info = original.createFromParcel(source);
        if (packageName.equals(info.packageName)) {
            info.signatures[0] = originalSignature;
        }
        return info;
    }
    ...
};
```

Both the deprecated `signatures` array and the `signingInfo` of Android 9 and newer are
filled, because an application may read either.

### The native level

Code that reads the certificate out of the apk file opens the apk through the libc. A
small native library replaces the `open`, `open64`, `openat` and `openat64` calls of
every loaded module and serves a copy of the original apk instead. The path of the apk
is found in the memory maps of the process, which is where the native code looks for it
as well.

### The start

`android:appComponentFactory` is the earliest point the platform offers: it asks the
factory for the application instance before the application class is loaded, so the
payload is in place before any native library of the application can cache the real
package manager. The factory that was in the manifest before is kept and still does the
actual instantiation, so an application that relies on its own factory keeps working.

---

## Project layout

| Path | Contents |
| --- | --- |
| `src/main/java/alienkrishn/qrylz/Qrylz.java` | the command line and the pipeline |
| `.../SignatureExtractor.java` | reads the original certificate out of the apk |
| `.../ManifestEditor.java` | patches the binary manifest with ARSCLib |
| `.../ApkOverlapper.java` | writes the apk with the original as its prefix |
| `.../DexInjector.java` | patches the payload dex with dexlib2 |
| `payload/` | the runtime half, compiled to `payload.dex` with the SDK `d8` |
| `native/` | the native hook, built with the NDK |

---

## Architectures

The tool itself is a plain java program, the jar runs on any jvm.

The **native hook** is built for every abi an android application can carry:

| abi | |
| --- | --- |
| `arm64-v8a` | 64 bit arm |
| `armeabi-v7a` | 32 bit arm |
| `x86_64` | 64 bit x86 |
| `x86` | 32 bit x86 |

The hook is only injected into a `lib/` directory the apk already has. Adding a directory
for an abi the apk does not support would make the package manager refuse to install it
on a device of that abi. An apk that carries `arm64-v8a` and `armeabi-v7a` libraries
gets the build of its own instruction set in each of them, so the bypass works on both.

The hook points the global offset table entries of the plt relocations of the loaded
modules at its own functions. The relocation says where the entry is, so the same code
works on every architecture - only the shape of the elf structures differs, and the
elf types of the platform take care of that.

---

## Third party libraries

| Library | Project | License | Used for |
| --- | --- | --- | --- |
| **ARSCLib** | [REAndroid/ARSCLib](https://github.com/REAndroid/ARSCLib) | Apache 2.0 | reading and writing the binary `AndroidManifest.xml`, the resource table and the apk |
| **smali-dexlib2** | [AOSP smali](https://github.com/google/smali) | Apache 2.0 | reading, patching and writing the dex files |
| **Picocli** | [remkop/picocli](https://github.com/remkop/picocli) | Apache 2.0 | the command line interface |
| **Guava** | [google/guava](https://github.com/google/guava) | Apache 2.0 | a dependency of dexlib2 |

The Android SDK (`d8`) and the Android NDK are used at build time only.

---

## Disclaimer

Qrylz is meant for **apks you own or are authorised to test** - your own application, an
application you contribute to, a lab build.

It bypasses signature verification. Using it on third party software defeats the licence
checks those applications rely on and is not the intended use. The authors are not
responsible for any misuse of this tool.

---

## License

```
MIT License

Copyright (c) 2026 Anon4You
```

See [LICENSE](LICENSE).
