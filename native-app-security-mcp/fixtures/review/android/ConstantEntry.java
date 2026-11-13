package example.review;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public final class ConstantEntry extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        new WebView(this).loadUrl("https://fixture.invalid/constant");
    }
}
