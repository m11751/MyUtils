package com.aidl.myutils.designpatterns.structural.proxy;

import android.os.Bundle;
import android.view.LayoutInflater;

import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.databinding.ActivityDesignPattenBinding;


/**
 * 代理模式例子
 * 输出结果:
 *  以下是原始对象执行结果:
 * result:5
 * 以下是代理对象执行结果:
 * Before add method
 * After add method
 * result2:5
 *
 * 说明:
 * 1.假设我们有一个接口 Calculator，它定义了一个方法 add：
 * 2.我们现在创建一个实现了 Calculator 接口的原始对象 CalculatorImpl：
 *3.我们可以使用原始对象来执行 add 方法：
 * 4.现在我们创建一个代理对象 CalculatorProxy，它也实现了 Calculator 接口：
 * 5.在这个代理对象中，我们将原始对象作为参数传递给代理对象的构造函数，然后在代理对象的 add 方法中调用原始对象的 add 方法，并在执行前后打印一些额外的信息。
 *  现在我们可以使用代理对象来执行 add 方法：
 *  从输出中可以看到，代理对象成功地调用了原始对象的 add 方法，并在执行前后打印了一些额外的信息。
 * 这个简单的代理模式的示例演示了如何使用代理对象来控制对另一个对象的访问，并在访问前后执行一些额外的操作。
 */
public class ProxyPattenActivity extends AppCompatActivity {
    ActivityDesignPattenBinding activityProxyPattenBinding;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activityProxyPattenBinding  = ActivityDesignPattenBinding.inflate(LayoutInflater.from(this));
        setContentView(activityProxyPattenBinding.getRoot());
        main();
    }

    private void main() {
        System.out.println("以下是原始对象执行结果:\n");
        Calculator calculator = new CalculatorImpl();
        int result = calculator.add(2, 3);
        System.out.println("result:" + result); // 输出 5

        System.out.println("以下是代理对象执行结果:\n");
        Calculator calculator2 = new CalculatorImpl();
        Calculator proxy = new CalculatorProxy(calculator2);
        int result2 = proxy.add(2, 3);
        System.out.println("result2:" + result2); // 输出 5

    }
}