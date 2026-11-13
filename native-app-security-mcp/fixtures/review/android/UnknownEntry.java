package example.review;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public final class UnknownEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new WebView(this).loadUrl(transform(getIntent().getStringExtra("fixture-unknown-input")));
    }
    private String transform(String ignored) { return "https://fixture.invalid/transformed"; }
}
