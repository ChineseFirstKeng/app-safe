package example.review;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public final class Entry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        navigate(new WebView(this), getIntent().getStringExtra("fixture-review-url"));
    }
    private void navigate(WebView view, String url) { view.loadUrl(url); }
}
