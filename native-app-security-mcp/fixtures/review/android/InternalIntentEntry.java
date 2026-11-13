package example.review;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
public final class InternalIntentEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Intent intent = new Intent();
        intent.putExtra("fixture-internal-key", "https://fixture.invalid/internal");
        new WebView(this).loadUrl(intent.getStringExtra("fixture-internal-key"));
    }
}
