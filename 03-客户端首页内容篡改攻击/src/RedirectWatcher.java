package com.sdmc.homewoo;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;

/** 仅用于授权测试：检测登录状态后跳转到自定义页面。 */
public final class RedirectWatcher {
    private static final String TAG = "HomewooRedirect";
    private static boolean started;
    private static View overlay;

    private RedirectWatcher() {}

    public static void start(Activity activity) {
        if (started) return;
        started = true;
        Handler handler = new Handler(Looper.getMainLooper());
        Runnable poll = new Runnable() {
            @Override public void run() {
                if (activity.isFinishing()) return;
                SharedPreferences secure = activity.getSharedPreferences("FlutterSecureStorage", Activity.MODE_PRIVATE);
                // 不持久化“已展示”状态：只要登录态仍存在，每次重新进入 MainActivity 都覆盖原首页。
                if (overlay == null && secure.getAll().size() > 2) {
                    showOverlay(activity);
                    return;
                }
                handler.postDelayed(this, 50L);
            }
        };
        handler.postDelayed(poll, 50L);
    }

    private static void showOverlay(Activity activity) {
        ViewGroup content = activity.findViewById(android.R.id.content);
        if (content == null || overlay != null) return;
        overlay = CustomHomeActivity.createHomeView(activity, () -> {
            ViewGroup parent = (ViewGroup) overlay.getParent();
            if (parent != null) parent.removeView(overlay);
            overlay = null;
        });
        content.addView(overlay, new ViewGroup.LayoutParams(-1, -1));
        overlay.bringToFront();
        Log.i(TAG, "login state detected; overlaying MainActivity with CustomHomeView");
    }
}
