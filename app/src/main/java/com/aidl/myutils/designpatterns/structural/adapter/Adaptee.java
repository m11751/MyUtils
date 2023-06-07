package com.aidl.myutils.designpatterns.structural.adapter;

// 需要适配的类
class Adaptee {
    void specificRequest() {
        System.out.println("Adaptee specificRequest() is called");
    }
}
