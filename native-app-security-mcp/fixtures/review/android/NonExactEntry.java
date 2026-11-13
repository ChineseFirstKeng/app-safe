package example.review;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public class NonExactEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        navigate(new WebView(this), getIntent().getStringExtra("fixture-virtual-input"));
    }
    protected void navigate(WebView view, String value) { view.loadUrl(value); }
}
