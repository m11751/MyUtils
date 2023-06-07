package com.aidl.myutils.designpatterns.structural.facede;

import android.os.Bundle;
import android.view.LayoutInflater;

import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.databinding.ActivityDesignPattenBinding;


/**
 * 外观模式（Facade Pattern）是一种结构型设计模式，它为子系统提供一组更高级别的接口，从而使子系统更容易使用。该模式隐藏了子系统的复杂性，并提供一个简单的接口以供客户端使用。
 * 上述示例中，SystemOne、SystemTwo和SystemThree是三个子系统，它们分别实现了不同的功能。Facade是一个外观类，提供了一个简单的接口facadeMethod()，该接口封装了三个子系统的复杂功能。客户端只需要使用Facade提供的接口即可完成一系列的操作。
 * 运行客户端代码的输出结果为：
 *
 * 调用外观类的facadeMethod()方法
 * 调用子系统1的methodOne()方法
 * 调用子系统2的methodTwo()方法
 * 调用子系统3的methodThree()方法
 *
 * 从输出结果可以看出，客户端只需要调用facadeMethod()方法即可完成一系列的操作，而不需要直接操作三个子系统的复杂功能。
 */
public class FacadePatternActivity extends AppCompatActivity {
    ActivityDesignPattenBinding activityDesignPattenBinding;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activityDesignPattenBinding  = ActivityDesignPattenBinding.inflate(LayoutInflater.from(this));
        setContentView(activityDesignPattenBinding.getRoot());
        main();
    }

    private void main() {
        Facade facade = new Facade();
        facade.facadeMethod();
    }
}