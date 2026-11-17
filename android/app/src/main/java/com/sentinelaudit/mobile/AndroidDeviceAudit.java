package com.sentinelaudit.mobile;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Locale;
import java.util.TimeZone;

/** Collects a small, read-only, user-consented inventory using public Android APIs. */
final class AndroidDeviceAudit {
    private static final int MAX_VISIBLE_APPS = 500;

    private AndroidDeviceAudit() { }

    static JSONObject collect(Context context) throws Exception {
        JSONObject root = new JSONObject();
        root.put("schema_version", 1);
        root.put("consent_confirmed", true);
        SimpleDateFormat timestamp = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        timestamp.setTimeZone(TimeZone.getTimeZone("UTC"));
        root.put("collected_at", timestamp.format(new Date()));

        JSONObject device = new JSONObject();
        device.put("manufacturer", Build.MANUFACTURER == null ? "Unknown" : Build.MANUFACTURER);
        device.put("model", Build.MODEL == null ? "Unknown" : Build.MODEL);
        device.put("android_version", Build.VERSION.RELEASE == null ? "Unknown" : Build.VERSION.RELEASE);
        device.put("sdk_int", Build.VERSION.SDK_INT);
        device.put("security_patch", Build.VERSION.SECURITY_PATCH == null ? "" : Build.VERSION.SECURITY_PATCH);
        root.put("device", device);

        JSONObject checks = new JSONObject();
        checks.put("device_info", checked("Android version, API level, manufacturer and model collected."));
        if (Build.VERSION.SECURITY_PATCH != null && Build.VERSION.SECURITY_PATCH.matches("\\d{4}-\\d{2}-\\d{2}")) {
            checks.put("security_patch", checked(Build.VERSION.SECURITY_PATCH, "Reported by Android Build.VERSION.SECURITY_PATCH."));
        } else {
            checks.put("security_patch", unavailable("Android did not expose a valid security patch date."));
        }

        KeyguardManager keyguard = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        if (keyguard != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            checks.put("secure_screen_lock", checked(keyguard.isDeviceSecure(), "Android KeyguardManager.isDeviceSecure()."));
        } else {
            checks.put("secure_screen_lock", unavailable("Secure-lock status is unavailable on this Android build."));
        }
        checks.put("adb_debugging", readGlobalBoolean(context, Settings.Global.ADB_ENABLED));
        checks.put("developer_options", readGlobalBoolean(context, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED));
        checks.put("play_protect", unavailable("Android does not provide a generally available API for another app to read the Play Protect verdict."));
        checks.put("storage_encryption", unavailable("Encryption state is not collected by this personal-device audit."));

        JSONArray apps = new JSONArray();
        Set<String> seenPackages = new HashSet<>();
        PackageManager manager = context.getPackageManager();
        Intent launcherIntent = new Intent(Intent.ACTION_MAIN);
        launcherIntent.addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> launchables = manager.queryIntentActivities(launcherIntent, 0);
        int omitted = 0;
        for (ResolveInfo item : launchables) {
            if (item.activityInfo == null || item.activityInfo.packageName == null) continue;
            String packageName = item.activityInfo.packageName;
            if (!seenPackages.add(packageName)) continue;
            if (apps.length() >= MAX_VISIBLE_APPS) {
                omitted++;
                continue;
            }
            try {
                PackageInfo info = manager.getPackageInfo(packageName, 0);
                JSONObject app = new JSONObject();
                CharSequence label = manager.getApplicationLabel(info.applicationInfo);
                app.put("name", label == null ? packageName : label.toString());
                app.put("package_name", packageName);
                app.put("version_name", info.versionName == null ? "" : info.versionName);
                app.put("version_code", Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ? info.getLongVersionCode() : info.versionCode);
                apps.put(app);
            } catch (PackageManager.NameNotFoundException | SecurityException ignored) {
                // Package visibility can change while collecting; that entry is simply omitted.
            }
        }
        String inventoryNote = "Only apps with launcher activities visible to this app are included; Android package visibility can hide other packages.";
        if (omitted > 0) inventoryNote += " Inventory capped at " + MAX_VISIBLE_APPS + " entries; " + omitted + " more launchable packages were omitted.";
        checks.put("visible_app_inventory", checked(apps.length(), inventoryNote));
        root.put("checks", checks);
        root.put("apps", apps);
        return root;
    }

    private static JSONObject checked(String detail) throws Exception {
        JSONObject check = new JSONObject();
        check.put("status", "checked");
        check.put("detail", detail);
        return check;
    }

    private static JSONObject checked(boolean value, String detail) throws Exception {
        JSONObject check = checked(detail);
        check.put("value", value);
        return check;
    }

    private static JSONObject checked(int value, String detail) throws Exception {
        JSONObject check = checked(detail);
        check.put("value", value);
        return check;
    }

    private static JSONObject checked(String value, String detail) throws Exception {
        JSONObject check = checked(detail);
        check.put("value", value);
        return check;
    }

    private static JSONObject unavailable(String detail) throws Exception {
        JSONObject check = new JSONObject();
        check.put("status", "unavailable");
        check.put("detail", detail);
        return check;
    }

    private static JSONObject readGlobalBoolean(Context context, String setting) throws Exception {
        try {
            boolean enabled = Settings.Global.getInt(context.getContentResolver(), setting, 0) == 1;
            return checked(enabled, "Read-only Android Settings.Global value.");
        } catch (RuntimeException error) {
            return unavailable("Android did not allow this settings check.");
        }
    }
}
