package com.aidl.myutils.network;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;


import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.R;
import com.aidl.myutils.databinding.ActivityHttpBinding;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;


import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * okhttp的例子，首先需要确保设备连接网络正常，否则会报错：
 * java.net.UnknownHostException: Unable to resolve host "www.baidu.com": No address associated with hostname
 * reference：<a href="https://blog.csdn.net/weixin_33788244/article/details/94032744">...</a>
 *
 * if not using android:usesCleartextTraffic="true" in AndroidManifest
 * will have error:
 * java.lang.RuntimeException: java.net.UnknownServiceException: CLEARTEXT communication to www.baidu.com not permitted by network security policy
 */
public class OkHttpActivity extends AppCompatActivity implements View.OnClickListener {
    ActivityHttpBinding activity_net;
    private static final String TAG = "evan";
    private static final String YOUTUBE_WEB = "https://www.youtube.com";
    private static final String BING_WEB = "https://www.bing.com";
    private static final String BAIDU_WEB = "http://www.baidu.com";
    private static final int NETWORK_TIME_OUT = 3 * 1000;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activity_net  = ActivityHttpBinding.inflate(LayoutInflater.from(this));
        setContentView(activity_net.getRoot());
        activity_net.textView.setText(OkHttpActivity.class.getName());
        activity_net.button.setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
       if (view.getId() == R.id.button){
           Log.i(TAG,"click..");
           sendRequestWithOkHttp();
       }
    }

    /**
     *  java.util.concurrent.TimeoutException 报错
     */
    private void sendRequestWithOkHttp(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    OkHttpClient client = new OkHttpClient();
                    Request request = new Request.Builder().url(BAIDU_WEB).build(); //request对象
                    Response response = client.newCall(request).execute();  //发送请求并返回数据
                    assert response.body() != null;
                    String responseDate = response.body().string();
                    showResponse(responseDate);
                } catch (Exception e) {
                    Log.i(TAG,"Exception:" + e);
                    throw new RuntimeException(e);
                }
            }
        }).start();
    }   //sendRequestWithHttpURLConnection

    private void showResponse(final String response){
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                activity_net.textView.setText(response);
                Log.i(TAG,"response:" + response);
            }
        });
    }
}