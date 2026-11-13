package example.review;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public final class OverwriteEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        String value = getIntent().getStringExtra("fixture-ignored-input");
        value = "https://fixture.invalid/replaced";
        new WebView(this).loadUrl(value);
    }
}
