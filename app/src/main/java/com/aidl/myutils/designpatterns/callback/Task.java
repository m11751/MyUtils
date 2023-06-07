package com.aidl.myutils.designpatterns.callback;

public class Task {
    public void execute(Callback callback) {
        // 模拟任务的耗时操作
        try {
            Thread.sleep(1000 * 10);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // 完成后调用回调方法
        callback.onComplete("Task completed");
    }
}