package com.aidl.myutils.designpatterns.structural.adapter;

import android.os.Bundle;
import android.view.LayoutInflater;

import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.databinding.ActivityDesignPattenBinding;


/**
 * 适配器模式是一种结构型设计模式，它允许将一个类的接口转换为客户希望的另一个接口。
 * 适配器模式通常用于系统需要使用现有的类，但这些类的接口与系统要求的接口不兼容的情况下。适配器模式的主要作用是解决接口不兼容的问题，使得原本由于接口不匹配而无法一起工作的那些类可以一起工作。
 * 示例代码中，目标接口 Target 定义了客户端所需的接口，适配器类 Adapter 将需要适配的类 Adaptee 转换为目标接口所需的接口。客户端通过调用 execute 方法来执行适配器适配后的操作。
 * 输出结果为：
 *
 * Adaptee specificRequest() is called
 * 适配器模式可以帮助我们在不改变现有代码的情况下，将不兼容的接口转换为兼容的接口，使得不同类之间可以更加灵活地协同工作。
 */
public class AdapterActivity extends AppCompatActivity {
    ActivityDesignPattenBinding activityDesignPattenBinding;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activityDesignPattenBinding = ActivityDesignPattenBinding.inflate(LayoutInflater.from(this));
        setContentView(activityDesignPattenBinding.getRoot());
        main();
    }

    private void main() {
        Client client = new Client();
        Target target = new Adapter();
        client.execute(target);
    }
}