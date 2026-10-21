# Qrylz

Command line tool that patches an Android APK so that **signature verification keeps
working after the APK has been re-signed**.

It is meant for **APKs you own or are authorised to test** - your own app, an app you
contribute to, a lab build. Using it to defeat the licence checks of third party apps is
not the intended use and may break their terms.

## What it does

1. **Merge** - a split set (`.apks` / `.xapk` / `.apkm`) is merged into one APK with
   APKEditor.
2. **Extract** - the original signing certificate is read from `META-INF/CERT.RSA` and
   the original `META-INF` folder is collected.
3. **Tiny origin** - the original `META-INF` folder is zipped into
   `assets/qrylz_origin.zip`. A few kilobytes instead of a second copy of the whole APK.
4. **Patch** - the Base64 of the original certificate replaces the `PLACEHOLDER_SIG`
   placeholder inside the payload dex (dexlib2), and the payload is merged into the
   application dex.
5. **Hook** - the application class gets a call to `QrylzPayload.install(Context)` in
   `attachBaseContext`. That installs a dynamic proxy in front of the package manager so
   the process keeps seeing the original certificate.
6. **Write** - the patched APK is written out. It is **not signed**; sign it with your
   own key afterwards.

The native part (`libqrylz_hook.so`) is optional and injected with `--lib`. It is what
lets the hook reach `ActivityThread.mPackageManager` on Android 9 and newer, where that
is a hidden API, and what serves the original signature blocks to code that reads the APK
file directly.

## Build

```bash
./gradlew shadowJar          # -> build/libs/qrylz.jar
./gradlew run --args="-i app.apk -o patched.apk"
```

Needs a JDK 17 and an Android SDK (for `d8`, used to build the payload dex). Point
`local.properties` at the SDK:

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

## Layout

| Path | Contents |
| --- | --- |
| `src/main/java/alienkrishn/qrylz/Qrylz.java` | CLI and pipeline |
| `src/main/java/alienkrishn/qrylz/SignatureExtractor.java` | certificate and `META-INF` extraction |
| `src/main/java/alienkrishn/qrylz/DexInjector.java` | dexlib2 patching |
| `payload/` | runtime half, compiled to `payload.dex` with the SDK `d8` |
