# Qrylz

Command line tool that patches an Android APK so that **signature verification keeps
working after the APK has been re-signed**.

It is meant for **APKs you own or are authorised to test** - your own app, an app you
contribute to, a lab build. Using it to defeat the licence checks of third party apps is
not the intended use and may break their terms.

## How it works

Three things have to be true for an app to keep working after it was re-signed:

| Check | Where | Qrylz |
| --- | --- | --- |
| the app asks the package manager for its own signature | java | the parcel creator of `PackageInfo` is replaced, so every package info that is unmarshalled reports the original certificate |
| the app reads the certificate out of the apk file | native | a small library redirects the opens of the apk to a copy of the original apk |
| the app must still start | - | `android:appComponentFactory` points at the payload, so it runs before the application class |

The original apk is kept **byte for byte** as the prefix of the patched apk, so the
payload can serve it without carrying a second copy around.

```
 patched apk
 +----------------------------------------------------+
 |  the original apk, unchanged  |  AndroidManifest.xml   <- patched
 |  (the payload serves this)    |  classes5.dex          <- the payload
 |                                |  lib/.../hook.so       <- the native hook
 +----------------------------------------------------+
 |  central directory, end record                      |
 +----------------------------------------------------+
```

Because the original bytes are already there, the apk only grows by the new entries and
one more central directory: **about 600 KB** instead of the 90 MB a second copy of the
apk would cost.

## Compared to the tools it replaces

| | MT Manager | NP Manager | Qrylz |
| --- | --- | --- | --- |
| certificate reported | a hard coded fake one | the original one | the original one |
| apk grows by | ~3.5 MB | ~1.3 MB | ~0.6 MB |
| application class | replaced | replaced | **kept**, the payload uses the component factory |
| apk kept inside the apk | a second full copy | the same bytes, reused | the same bytes, reused |

The certificate is the important difference: the fake certificate of MT Manager does not
match the one the application expects, so a check against the store certificate still
fails.

## Build

```bash
./gradlew shadowJar          # -> build/libs/qrylz.jar
./gradlew run --args="-i app.apk -o patched.apk --lib native/build/libqrylz_hook.so"
```

Needs a JDK 17 and the Android SDK for `d8`, which builds the payload dex. The native
hook is built with the NDK:

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
      -DCMAKE_BUILD_TYPE=Release -B native/build native
cmake --build native/build
```

`local.properties` points at the SDK:

```properties
sdk.dir=/path/to/android-sdk
```

## Usage

```
Usage: qrylz [-hV] -i=<apk> -o=<apk> [--payload=<dex>] [--lib=<so>]

  -i, --input=<apk>    Input APK or split APK set (.apk, .apks, .xapk, .apkm)
  -o, --output=<apk>   Output APK (not signed)
      --payload=<dex>  Payload dex to inject. Defaults to the bundled payload.dex.
      --lib=<so>       Native hook to inject as lib/arm64-v8a/libqrylz_hook.so
  -h, --help           Show this help message and exit.
  -V, --version        Print version information and exit.
```

The output is **not signed**. Sign it with your own key afterwards:

```bash
zipalign -f -p 4 patched.apk aligned.apk
apksigner sign --ks my.jks --out signed.apk aligned.apk
```

## Layout

| Path | Contents |
| --- | --- |
| `src/main/java/alienkrishn/qrylz/Qrylz.java` | CLI and pipeline |
| `.../SignatureExtractor.java` | reads the original certificate |
| `.../ManifestEditor.java` | patches the binary manifest with ARSCLib |
| `.../ApkOverlapper.java` | writes the apk with the original as its prefix |
| `.../DexInjector.java` | dexlib2 patching of the payload |
| `payload/` | the runtime half, compiled to `payload.dex` with the SDK `d8` |
| `native/` | the native hook, built with the NDK |

## Credits

The mechanism follows the public work on the subject, in particular
[ApkSignatureKillerEx](https://github.com/L-JINBIN/ApkSignatureKillerEx) and
[APKKiller](https://github.com/aimardcr/APKKiller).
