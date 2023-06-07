package com.aidl.myutils.designpatterns.structural.adapter;

// 适配器类,实现目标接口
class Adapter implements Target {
    private final Adaptee adaptee = new Adaptee();

    @Override
    public void request() {
        adaptee.specificRequest();
    }
}
