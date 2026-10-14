package com.sdmc.homewoo;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** 仅用于授权安全测试：登录成功后展示的替换首页。 */
public class CustomHomeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(createHomeView(this, null));
    }

    /** 在宿主 Activity 内容层创建自定义首页，避免原 Flutter Activity 切换闪现。 */
    public static View createHomeView(Activity host, final Runnable onReturn) {
        LinearLayout root = new LinearLayout(host);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(48, 96, 48, 48);
        root.setBackgroundColor(Color.WHITE);
        root.setClickable(true);
        root.setFocusable(true);
        TextView title = new TextView(host);
        title.setText("自定义首页");
        title.setTextSize(30);
        title.setTextColor(Color.rgb(45, 20, 80));
        title.setGravity(Gravity.CENTER);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));
        TextView detail = new TextView(host);
        detail.setText("此页面由二次打包客户端注入\n登录成功后替换原 Homewoo 首页");
        detail.setTextSize(18);
        detail.setGravity(Gravity.CENTER);
        detail.setPadding(0, 36, 0, 48);
        root.addView(detail, new LinearLayout.LayoutParams(-1, -2));
        Button original = new Button(host);
        original.setText("打开测试落地页");
        original.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://127.0.0.1:18080/test-landing"));
            host.startActivity(intent);
        });
        root.addView(original, new LinearLayout.LayoutParams(-1, -2));
        return root;
    }
}
