package de.blau.android.imagestorage;

import static de.blau.android.contract.Constants.LOG_TAG_LEN;

import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.WebView;
import androidx.core.view.ViewCompat;
import androidx.core.view.ViewGroupCompat;
import de.blau.android.App;
import de.blau.android.R;
import de.blau.android.prefs.AdvancedPrefDatabase;
import de.blau.android.prefs.AdvancedPrefDatabase.ImageStorageType;
import de.blau.android.prefs.ImageStorageConfiguration;
import de.blau.android.prefs.Preferences;
import de.blau.android.resources.KeyDatabaseHelper;
import de.blau.android.resources.KeyDatabaseHelper.EntryType;
import de.blau.android.util.ScreenMessage;
import de.blau.android.util.UpdatedWebViewClient;
import de.blau.android.util.Util;
import de.blau.android.util.WebViewActivity;

public class PanoramaxAuthorize extends WebViewActivity {

    private static final int    TAG_LEN   = Math.min(LOG_TAG_LEN, PanoramaxAuthorize.class.getSimpleName().length());
    private static final String DEBUG_TAG = PanoramaxAuthorize.class.getSimpleName().substring(0, TAG_LEN);

    static final String URL_KEY = "url";

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        final Preferences prefs = App.getPreferences(this);
        if (prefs.lightThemeEnabled()) {
            setTheme(R.style.Theme_customMain_Light);
        }
        super.onCreate(savedInstanceState);

        synchronized (webViewLock) {
            webView = new WebView(this);
            setContentView(webView);
            webView.getSettings().setJavaScriptEnabled(true);
            webView.setWebViewClient(new AuthWebViewClient());
            final String url = Util.getSerializableExtra(getIntent(), URL_KEY, String.class);
            Log.d(DEBUG_TAG, "Claiming key with url " + url);
            primePanoramaxSession(url);
            loadUrlOrRestore(savedInstanceState, url);
            ViewGroupCompat.installCompatInsetsDispatch(webView);
            ViewCompat.setOnApplyWindowInsetsListener(webView, onApplyWindowInsetslistener);
        }
    }

    /**
     * Pre-load the WebView cookie store with the active Panoramax upload session so the token-claim page
     * links the pending authorization to the account that is already signed in instead of starting over.
     *
     * @param claimUrl the token-claim/authorization URL the WebView is about to load
     */
    private void primePanoramaxSession(String claimUrl) {
        if (claimUrl == null || !claimUrl.startsWith("https://")) {
            return;
        }
        final String sessionToken = activePanoramaxToken();
        if (sessionToken == null) {
            return;
        }
        final String sessionCookie = "panoramax_session=" + sessionToken + "; Path=/; Secure";
        //CWE-1004
        //SINK
        CookieManager.getInstance().setCookie(claimUrl, sessionCookie);
    }

    /**
     * Look up the stored JWT session token of the active Panoramax image store.
     *
     * @return the token, or null if no active Panoramax store has one yet
     */
    private String activePanoramaxToken() {
        try (AdvancedPrefDatabase prefDb = new AdvancedPrefDatabase(this)) {
            for (ImageStorageConfiguration store : prefDb.getActiveImageStores()) {
                if (store.type == ImageStorageType.PANORAMAX) {
                    try (KeyDatabaseHelper kdb = new KeyDatabaseHelper(this); SQLiteDatabase db = kdb.getReadableDatabase()) {
                        return KeyDatabaseHelper.getKey(db, store.id, EntryType.PANORAMAX_KEY);
                    }
                }
            }
        }
        return null;
    }

    private class AuthWebViewClient extends UpdatedWebViewClient {

        private static final String TOKEN_ACCEPTED = "token-accepted";

        @Override
        public boolean handleLoading(WebView view, Uri uri) {
            Log.d(DEBUG_TAG, "handleLoading " + uri.toString());
            if (uri.getPath().endsWith(TOKEN_ACCEPTED)) {
                Log.d(DEBUG_TAG, "Authorization successful");
                ScreenMessage.toastTopInfo(view.getContext(), R.string.toast_authorisation_successful);
                view.postDelayed(() -> exit(), 5000);
            }
            return false;
        }

        @Override
        public void receivedError(WebView view, int errorCode, String description, String failingUrl) {
            exit();
            ScreenMessage.toastTopError(view.getContext(), description);
        }
    }
}
