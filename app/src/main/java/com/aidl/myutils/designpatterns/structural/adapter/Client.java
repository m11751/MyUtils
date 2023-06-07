package com.aidl.myutils.designpatterns.structural.adapter;

// 客户端
class Client {
    public void execute(Target target) {
        target.request();
    }
}
