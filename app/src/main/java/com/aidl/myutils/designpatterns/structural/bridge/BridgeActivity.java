package com.aidl.myutils.designpatterns.structural.bridge;

import android.os.Bundle;
import android.view.LayoutInflater;

import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.databinding.ActivityDesignPattenBinding;

/**
 * 桥接模式，圆形类，矩形类继承形状类
 * 红色，绿色继承颜色类
 *
 * 画一个红色圆形，绿色矩形
 * 2023-03-26 10:22:57.954  2752-2752  System.out              com.example.test2                    I  Draw a circle, Fill with red color.
 * 2023-03-26 10:22:57.954  2752-2752  System.out              com.example.test2                    I  Draw a rectangle, Fill with green color.
 */
public class BridgeActivity extends AppCompatActivity {
    ActivityDesignPattenBinding activityDesignPattenBinding ;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activityDesignPattenBinding  = ActivityDesignPattenBinding.inflate(LayoutInflater.from(this));
        setContentView(activityDesignPattenBinding.getRoot());
        main();
    }

    private void main() {
        Shape circle = new Circle(new RedColor());
        circle.draw();
        Shape rectangle = new Rectangle(new GreenColor());
        rectangle.draw();
    }
}