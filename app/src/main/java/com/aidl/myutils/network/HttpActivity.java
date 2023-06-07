package com.aidl.myutils.network;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;

import com.aidl.myutils.R;
import com.aidl.myutils.databinding.ActivityHttpBinding;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * http example,no using android:usesCleartextTraffic="true" in AndroidManifest
 */
public class HttpActivity extends AppCompatActivity implements View.OnClickListener {
    ActivityHttpBinding activity_net;
    private static final String TAG = "evan";
    private static final String YOUTUBE_WEB = "https://www.youtube.com";
    private static final String BING_WEB = "https://www.bing.com";
    private static final String BAIDU_WEB = "https://www.baidu.com";
    private static final int NETWORK_TIME_OUT = 3 * 1000;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activity_net  = ActivityHttpBinding.inflate(LayoutInflater.from(this));
        setContentView(activity_net.getRoot());
        activity_net.textView.setText(HttpActivity.class.getName());
        activity_net.button.setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
       if (view.getId() == R.id.button){
           Log.i(TAG,"click..");
           sendRequestWithHttpURLConnection();
       }
    }

    /**
     *  java.util.concurrent.TimeoutException 报错
     */
    private void sendRequestWithHttpURLConnection(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                HttpURLConnection connection = null;
                BufferedReader reader = null;
                try {
                    URL url = new URL(BAIDU_WEB);
                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("GET");
                    connection.setConnectTimeout(NETWORK_TIME_OUT);
                    connection.setReadTimeout(NETWORK_TIME_OUT);
                    int responseCode = connection.getResponseCode(); //发送http请求
                    InputStream in = null;
                    switch (responseCode){
                        case HttpURLConnection.HTTP_NOT_FOUND:
                            Log.i(TAG,"404 error");
                            break;
                        case HttpURLConnection.HTTP_INTERNAL_ERROR:
                            Log.i(TAG,"500 error");
                            break;
                        default:
                            in = connection.getInputStream();
                    }
                    reader = new BufferedReader(new InputStreamReader(in)); //流读取
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null){
                        response.append(line);
                    }
                    showResponse(response.toString());
                } catch (Exception e) {
                    Log.i(TAG,"Exception.." + e);
                    throw new RuntimeException(e);
                }finally {
                    if (reader != null){
                        try {
                            reader.close();
                        }catch (IOException e){
                            Log.i(TAG,"Exception.." + e);
                            e.printStackTrace();
                        }
                    }if (connection != null){
                        Log.i(TAG,"connection null" );
                        connection.disconnect();
                    }
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