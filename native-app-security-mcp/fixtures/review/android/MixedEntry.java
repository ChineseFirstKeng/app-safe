package example.review;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public final class MixedEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        WebView view = new WebView(this);
        navigate(view, "https://fixture.invalid/fixed");
        navigate(view, getIntent().getStringExtra("fixture-mixed-input"));
    }
    private void navigate(WebView view, String value) { view.loadUrl(value); }
}
