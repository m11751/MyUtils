package com.aidl.myutils.designpatterns.callback;

import android.os.Bundle;
import android.view.LayoutInflater;

import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.databinding.ActivityDesignPattenBinding;


/**
 * 回调是一种设计模式，通过该模式，对象可以将方法作为参数传递给其他对象，以便在需要时调用该方法。回调通常用于异步编程，其中方法的执行在不同的线程上，以避免阻塞主线程。
 * 在上面的示例中，Task 类代表一个执行耗时操作的任务，该任务需要一个回调接口 Callback 来通知任务完成。Main 类创建了一个 Task 实例，
 * 并调用其 execute() 方法，传入一个匿名回调对象。在回调方法中，打印任务完成的结果。最后，Main 类打印出任务开始的消息。
 *输出结果应该如下所示：
 * 2023-03-25 17:08:43.478 24351-24351 System.out              com.example.test2                    I  Task 1
 * 2023-03-25 17:08:53.480 24351-24351 System.out              com.example.test2                    I  Task completed
 * 2023-03-25 17:08:53.481 24351-24351 System.out              com.example.test2                    I  Task 2
 */
public class CallbackActivity extends AppCompatActivity {
    ActivityDesignPattenBinding activityDesignPattenBinding;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        activityDesignPattenBinding  = ActivityDesignPattenBinding.inflate(LayoutInflater.from(this));
        setContentView(activityDesignPattenBinding.getRoot());
        main();
    }

    private void main() {
        System.out.println("Task 1");
        Task task = new Task();
        task.execute(new Callback() {
            @Override
            public void onComplete(String result) {
                System.out.println(result);
            }
        });
        System.out.println("Task 2");
    }
}