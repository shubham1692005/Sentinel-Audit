package com.sentinelaudit.mobile;

import android.app.Activity;
import android.app.DownloadManager;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.net.URI;
import java.util.Locale;

import com.google.firebase.FirebaseApp;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.DocumentSnapshot;

/** Android client for the existing Sentinel Audit server and its same-origin REST API. */
public final class MainActivity extends Activity {
    private static final String PREFS = "sentinel_mobile";
    private static final String SERVER_KEY = "server_url";
    private WebView webView;
    private ProgressBar progress;
    private String serverUrl;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(0xff0b1220);
        getWindow().setNavigationBarColor(0xff0b1220);
        try { FirebaseApp.initializeApp(this); } catch (Exception ignored) { }
        serverUrl = getPreferences(MODE_PRIVATE).getString(SERVER_KEY, "");
        buildShell();
        if (serverUrl.isEmpty()) checkFirebaseConfigAndConnect();
        else webView.loadUrl(serverUrl);
    }

    private void checkFirebaseConfigAndConnect() {
        try {
            FirebaseFirestore.getInstance().collection("config").document("server").get()
                .addOnSuccessListener(doc -> {
                    if (doc != null && doc.exists()) {
                        String cloudUrl = doc.getString("url");
                        String validated = normalizeServer(cloudUrl);
                        if (validated != null) {
                            serverUrl = validated;
                            getPreferences(MODE_PRIVATE).edit().putString(SERVER_KEY, serverUrl).apply();
                            webView.loadUrl(serverUrl);
                            return;
                        }
                    }
                    showServerDialog(false);
                })
                .addOnFailureListener(e -> showServerDialog(false));
        } catch (Exception e) {
            showServerDialog(false);
        }
    }

    private void buildShell() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xfff6f8fb);

        LinearLayout bar = new LinearLayout(this);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(16), dp(8), dp(10), dp(8));
        bar.setBackgroundColor(0xff0b1220);
        TextView title = new TextView(this);
        title.setText("Sentinel Audit");
        title.setTextColor(0xffffffff);
        title.setTextSize(18);
        title.setTypeface(null, 1);
        bar.addView(title, new LinearLayout.LayoutParams(0, dp(44), 1));
        Button sections = new Button(this);
        sections.setText("Menu");
        sections.setTextSize(12);
        sections.setOnClickListener(v -> showSections());
        bar.addView(sections, new LinearLayout.LayoutParams(-2, dp(42)));
        Button settings = new Button(this);
        settings.setText("Server");
        settings.setTextSize(12);
        settings.setOnClickListener(v -> showServerDialog(true));
        bar.addView(settings, new LinearLayout.LayoutParams(-2, dp(42)));
        root.addView(bar);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        progress.setVisibility(View.GONE);
        root.addView(progress, new LinearLayout.LayoutParams(-1, dp(3)));

        webView = new WebView(this);
        WebSettings web = webView.getSettings();
        web.setJavaScriptEnabled(true); // Required by the existing first-party web client.
        web.setDomStorageEnabled(true);
        web.setAllowFileAccess(false);
        web.setAllowContentAccess(false);
        web.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.setJavaScriptCanOpenWindowsAutomatically(false);
        web.setSupportMultipleWindows(false);
        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(webView, false);
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri target = request.getUrl();
                if (sameServer(target)) return false;
                openExternal(target);
                return true;
            }

            @Override public void onPageStarted(WebView view, String url, android.graphics.Bitmap icon) {
                progress.setVisibility(View.VISIBLE);
            }

            @Override public void onPageFinished(WebView view, String url) {
                progress.setVisibility(View.GONE);
                CookieManager.getInstance().flush();
            }

            @Override public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    progress.setVisibility(View.GONE);
                    Toast.makeText(MainActivity.this, "Can't reach the Sentinel server. Check the phone's Wi-Fi and server address.", Toast.LENGTH_LONG).show();
                }
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override public void onProgressChanged(WebView view, int value) {
                progress.setProgress(value);
                progress.setVisibility(value >= 100 ? View.GONE : View.VISIBLE);
            }
        });
        webView.addJavascriptInterface(new AndroidAuditBridge(), "SentinelAndroid");
        webView.setDownloadListener(new DownloadListener() {
            @Override public void onDownloadStart(String url, String userAgent, String disposition, String mime, long size) {
                download(url, userAgent, disposition, mime);
            }
        });
        root.addView(webView, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
    }

    private final class AndroidAuditBridge {
        @JavascriptInterface
        public void requestAndroidDeviceAudit() {
            runOnUiThread(() -> beginAndroidDeviceAudit());
        }

        @JavascriptInterface
        public void requestReportDownload(String path, String filename) {
            runOnUiThread(() -> downloadReportToDevice(path, filename));
        }
    }

    private void beginAndroidDeviceAudit() {
        if (!"https".equalsIgnoreCase(Uri.parse(serverUrl).getScheme())) {
            new AlertDialog.Builder(this)
                .setTitle("Secure server required")
                .setMessage("Android device audit data can include app names and versions. Configure Sentinel Audit with a trusted HTTPS address before sending this data. No device data was collected.")
                .setPositiveButton("OK", null)
                .show();
            return;
        }
        String consent = "This read-only audit will send to your Sentinel Audit server:\n\n"
            + "• Phone manufacturer, model, Android version and security patch date\n"
            + "• Screen-lock, USB-debugging and developer-options status where Android permits\n"
            + "• Names, package names and versions of launcher-visible apps\n\n"
            + "Some checks may be unavailable. Android can hide installed packages. This does not inspect app data, files, photos, messages or credentials, and it does not run exploits. App versions are inventory evidence, not proof of a vulnerability. The inventory is encrypted in the Sentinel database. Start only for a device you own or are authorized to assess.";
        new AlertDialog.Builder(this)
            .setTitle("Audit this Android device?")
            .setMessage(consent)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Start audit", (dialog, which) -> collectAndroidDeviceAudit())
            .show();
    }

    private void collectAndroidDeviceAudit() {
        Toast.makeText(this, "Collecting consented device settings and visible app versions…", Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            try {
                String payload = AndroidDeviceAudit.collect(this).toString();
                runOnUiThread(() -> {
                    if (webView == null || webView.getUrl() == null || !sameServer(Uri.parse(webView.getUrl()))) {
                        Toast.makeText(this, "Return to the signed-in Sentinel workspace to submit this audit.", Toast.LENGTH_LONG).show();
                        return;
                    }
                    String script = "window.SentinelAudit && window.SentinelAudit.onAndroidDeviceAuditCollected(" + payload + ");";
                    webView.evaluateJavascript(script, ignored -> { });
                });
            } catch (Exception error) {
                runOnUiThread(() -> Toast.makeText(this, "Could not collect the Android audit evidence.", Toast.LENGTH_LONG).show());
            }
        }, "sentinel-android-audit").start();
    }

    private void showServerDialog(boolean allowCancel) {
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setHint("https://your-cloud-run-url or http://laptop-ip:8080");
        input.setText(serverUrl);
        input.setSelectAllOnFocus(true);
        TextView note = new TextView(this);
        note.setText("Enter your Cloud / Firebase HTTPS server URL (for 24/7 access with laptop off) or local laptop address.");
        note.setTextSize(13);
        note.setPadding(dp(24), dp(6), dp(24), dp(6));
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.addView(note);
        body.addView(input, new LinearLayout.LayoutParams(-1, dp(52)));
        AlertDialog.Builder dialog = new AlertDialog.Builder(this)
            .setTitle("Connect to Sentinel Audit")
            .setView(body)
            .setPositiveButton("Connect", null);
        if (allowCancel) dialog.setNegativeButton("Cancel", (d, w) -> d.dismiss());
        AlertDialog shown = dialog.create();
        shown.setOnShowListener(ignored -> shown.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String validated = normalizeServer(input.getText().toString());
            if (validated == null) {
                input.setError("Enter a valid server origin, such as http://192.168.1.20:8080");
                return;
            }
            serverUrl = validated;
            getPreferences(MODE_PRIVATE).edit().putString(SERVER_KEY, serverUrl).apply();
            shown.dismiss();
            webView.loadUrl(serverUrl);
        }));
        shown.show();
    }

    /** Uses the existing website's own navigation handlers; no mobile copy of business logic. */
    private void showSections() {
        String[] labels = {"Overview", "Assets", "Findings", "Assessments", "Compliance", "Activity", "Reports", "Settings"};
        new AlertDialog.Builder(this).setTitle("Sentinel Audit")
            .setItems(labels, (dialog, index) -> {
                String selector = index == labels.length - 1 ? "#profile" : "[data-view='" + labels[index] + "']";
                String script = "(function(){var el=document.querySelector(" + jsString(selector) + ");if(el){el.click();return true;}return false;})()";
                webView.evaluateJavascript(script, result -> {
                    if ("false".equals(result)) Toast.makeText(this, "Sign in to open workspace sections.", Toast.LENGTH_SHORT).show();
                });
            }).setNegativeButton("Close", null).show();
    }

    private String jsString(String value) {
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    private String normalizeServer(String text) {
        try {
            URI uri = URI.create(text.trim());
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!(scheme.equals("http") || scheme.equals("https")) || uri.getHost() == null || uri.getUserInfo() != null) return null;
            if (uri.getRawQuery() != null || uri.getRawFragment() != null) return null;
            String path = uri.getPath();
            if (path != null && !path.isEmpty() && !path.equals("/")) return null;
            int port = uri.getPort();
            if (port < -1 || port > 65535) return null;
            return scheme + "://" + uri.getRawAuthority() + "/";
        } catch (Exception ignored) { return null; }
    }

    private boolean sameServer(Uri target) {
        try {
            Uri base = Uri.parse(serverUrl);
            return target.getScheme() != null && target.getScheme().equalsIgnoreCase(base.getScheme())
                && target.getHost() != null && target.getHost().equalsIgnoreCase(base.getHost())
                && target.getPort() == base.getPort();
        } catch (Exception ignored) { return false; }
    }

    private void openExternal(Uri target) {
        String scheme = target.getScheme();
        if (scheme == null || !(scheme.equals("https") || scheme.equals("http"))) return;
        try { startActivity(new Intent(Intent.ACTION_VIEW, target)); }
        catch (Exception ignored) { Toast.makeText(this, "No browser is available for this link.", Toast.LENGTH_SHORT).show(); }
    }

    private void download(String url, String userAgent, String disposition, String mime) {
        try {
            DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
            request.setTitle(disposition != null && disposition.contains("filename") ? "Sentinel Audit report" : "Sentinel Audit download");
            request.setDescription("Downloading from your Sentinel Audit server");
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "Sentinel-Audit-report." + (mime != null && mime.contains("pdf") ? "pdf" : "json"));
            String cookie = CookieManager.getInstance().getCookie(url);
            if (cookie != null) request.addRequestHeader("Cookie", cookie);
            if (userAgent != null) request.addRequestHeader("User-Agent", userAgent);
            if (mime != null) request.setMimeType(mime);
            ((DownloadManager)getSystemService(Context.DOWNLOAD_SERVICE)).enqueue(request);
            Toast.makeText(this, "Report download started", Toast.LENGTH_SHORT).show();
        } catch (Exception error) {
            Toast.makeText(this, "Could not start the download", Toast.LENGTH_LONG).show();
        }
    }

    private void downloadReportToDevice(String path, String filename) {
        try {
            if (path == null || !path.matches("^/api/reports/(pdf|json|html)\\?[^#]*$")
                || filename == null || !filename.matches("[A-Za-z0-9._-]{1,100}")) {
                Toast.makeText(this, "Invalid report download request", Toast.LENGTH_LONG).show();
                return;
            }
            Uri base = Uri.parse(serverUrl);
            Uri reportUri = Uri.parse(base.getScheme() + "://" + base.getAuthority() + path);
            if (!sameServer(reportUri)) {
                Toast.makeText(this, "Report URL does not match the configured server", Toast.LENGTH_LONG).show();
                return;
            }
            String reportUrl = reportUri.toString();
            String cookie = CookieManager.getInstance().getCookie(reportUrl);
            if (cookie == null || !cookie.contains("audit_session=")) {
                Toast.makeText(this, "Please sign in again before downloading the report", Toast.LENGTH_LONG).show();
                return;
            }
            String mime = filename.toLowerCase(Locale.ROOT).endsWith(".pdf") ? "application/pdf" :
                filename.toLowerCase(Locale.ROOT).endsWith(".json") ? "application/json" : "text/html";
            DownloadManager.Request request = new DownloadManager.Request(reportUri);
            request.setTitle(filename);
            request.setDescription("Downloading from your Sentinel Audit server");
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, filename);
            request.addRequestHeader("Cookie", cookie);
            request.addRequestHeader("User-Agent", webView.getSettings().getUserAgentString());
            request.setMimeType(mime);
            ((DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE)).enqueue(request);
            Toast.makeText(this, "Report download started; check Downloads", Toast.LENGTH_LONG).show();
        } catch (Exception error) {
            Toast.makeText(this, "Could not start the report download", Toast.LENGTH_LONG).show();
        }
    }

    @Override public void onBackPressed() {
        if (webView != null && webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    @Override protected void onDestroy() {
        if (webView != null) { webView.stopLoading(); webView.destroy(); }
        super.onDestroy();
    }

    private int dp(int value) { return (int)(value * getResources().getDisplayMetrics().density + 0.5f); }
}
