package com.aidl.myutils.designpatterns.structural.decorator;

import android.os.Bundle;
import android.view.LayoutInflater;

import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.databinding.ActivityDesignPattenBinding;

/**
 * 装饰模式：Decorator Patter
 * 不改变原有接口，使用新接口动态增加新功能
 * 输出结果：
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Circle with normal border:
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Drawing a Circle.
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Circle of red border:
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Drawing a Circle.
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Border Color: Red
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Rectangle of blue border:
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Draw a rectangle
 * 2023-03-27 07:07:47.621  8073-8073  System.out              com.example.test2                    I  Border Color: Blue
 */
public class DecoratorActivity extends AppCompatActivity {
    ActivityDesignPattenBinding activityDesignPattenBinding;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activityDesignPattenBinding  = ActivityDesignPattenBinding.inflate(LayoutInflater.from(this));
        setContentView(activityDesignPattenBinding.getRoot());
        main();
    }

    private void main() {
        Shape circle = new Circle();

        Shape redCircle = new RedShapeDecorator(new Circle());
        Shape blueRectangle = new BlueShapeDecorator(new Rectangle());

        System.out.println("Circle with normal border:");
        circle.draw();

        System.out.println("\nCircle of red border:");
        redCircle.draw();

        System.out.println("\nRectangle of blue border:");
        blueRectangle.draw();
    }
}