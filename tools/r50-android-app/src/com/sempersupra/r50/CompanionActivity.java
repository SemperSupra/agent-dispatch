package com.sempersupra.r50;

import android.app.Activity;
import android.os.Bundle;
import android.os.Build;
import android.widget.TextView;

public final class CompanionActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView label = new TextView(this);
        label.setText("R50_COMPANION_READY");
        label.setTextSize(20);
        setContentView(label);
        // Private app state is a verifier-only sandbox oracle, not an
        // enrollment certificate or a production identity/credential.
        if (!getSharedPreferences("r50_oracle", MODE_PRIVATE).edit()
                .putString("status", "R50_LAUNCHED")
                .putInt("android_api", Build.VERSION.SDK_INT)
                .commit()) {
            throw new IllegalStateException("private sandbox oracle persistence failed");
        }
    }
}
