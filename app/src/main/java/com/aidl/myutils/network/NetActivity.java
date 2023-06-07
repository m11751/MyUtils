package com.aidl.myutils.network;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.webkit.WebViewClient;

import com.aidl.myutils.databinding.ActivityNetBinding;

public class NetActivity extends AppCompatActivity {
    private static final String GOOGLE_WEB = "http://www.google.com/ncr";
    private static final String YOUTUBE_WEB = "http://www.youtube.com";
    ActivityNetBinding activity_net;
    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activity_net  = ActivityNetBinding.inflate(LayoutInflater.from(this));
        setContentView(activity_net.getRoot());
        activity_net.webviewMain.getSettings().setJavaScriptEnabled(true);
        activity_net.webviewMain.setWebViewClient(new WebViewClient());
        activity_net.webviewMain.loadUrl(YOUTUBE_WEB);
    }
}