package example.review;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public final class MergeEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        String value;
        if (getIntent().getBooleanExtra("fixture-switch", false)) value = "https://fixture.invalid/branch";
        else value = getIntent().getStringExtra("fixture-merge-input");
        navigate(new WebView(this), value);
    }
    private void navigate(WebView view, String value) { view.loadUrl(value); }
}
