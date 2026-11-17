# Sentinel Audit for Android

This is a separate Android client for the existing Sentinel Audit installation. It loads the existing responsive web client from the user's configured server URL, so the existing authentication, REST API, scanner, assessments, findings, evidence, risk/GRC views, and report generation continue to run on the same backend and SQLite database. The Android client contains no scanner and stores no assessment records locally.

## Build and install

1. Install Android Studio with Android SDK Platform 35 and a JDK supported by Android Gradle Plugin 8.7.3.
2. Open this `android` directory in Android Studio and allow Gradle sync.
3. Select the `app` run configuration and deploy to an Android phone/emulator, or use **Build > Build APK(s)**. The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.
4. On first launch, enter the Sentinel server URL. For a VPS, use its HTTPS hostname such as `https://sentinel.example.com/`; for a trusted LAN deployment, use the server's LAN URL. Use **Server** in the app toolbar later to change it.
5. Sign in using the existing Sentinel account. Use the app on the same trusted LAN/hotspot as the laptop host.

The app uses the same-origin website/API and Android's first-party cookie store. Backend role checks, project scoping, CSRF protections, and scan authorization remain enforced by the existing server. Scan jobs run on the server and continue if the app is closed.

## Android Device Audit

The Android app includes a separate **Audit this Android device** action in the signed-in workspace. The user taps Start on a native consent screen before collection. The audit is read-only and is distinct from Nmap network assessments and local checks of the Sentinel server.

The companion collects model, manufacturer, Android version/API level, security patch date, secure screen-lock state, ADB/developer-options state, and names/package names/versions for launcher-visible apps returned by Android's package-visibility API. It does not request runtime permissions, inspect app data/files/messages/credentials, or execute exploits. The app inventory is encrypted in SQLite with the stable `AUDIT_SECRET` and is decrypted only for authenticated assessment/report responses.

Android can hide installed packages from ordinary apps, so the inventory is limited to launcher-visible apps and is not complete. Play Protect verdict and storage-encryption state are recorded as unavailable; the companion does not claim to verify them. App version inventory alone is not matched to CVEs because package names and version strings do not provide reliable vendor advisory applicability. Patch age is a review signal, not proof of an unpatched vulnerability.

Device audit submission requires a trusted HTTPS Sentinel server URL. HTTP server URLs remain usable for ordinary local web access, but the Android audit action will explain that no collection is sent over plaintext HTTP. The server must have a stable `AUDIT_SECRET` of at least 32 characters for encrypted inventory storage. For a VPS, use the Caddy HTTPS deployment; a LAN deployment needs a trusted HTTPS endpoint before using this feature.

## Network and security

The server must be listening on an address reachable from the phone. For VPS use, the hostname must resolve to the VPS and HTTPS must be configured. For LAN use, the host firewall must allow the app port on the trusted private network. A hotspot may isolate clients; if the phone cannot reach the server URL, use a network that permits the connection or configure routing accordingly. The mobile app does not attempt to bypass isolation or firewall controls.

Cleartext HTTP is enabled in this app so it can connect to a private LAN host using the existing default deployment. HTTP does not encrypt traffic. Use HTTPS with a trusted certificate for production or untrusted networks. The embedded browser keeps navigation on the configured server; external HTTP(S) links open in the phone browser. Third-party cookies and local file access are disabled.

The Android audit is a distinct job type handled by the existing authenticated API, assessment history, and technical report pipeline. The existing Nmap workflow remains unchanged.
