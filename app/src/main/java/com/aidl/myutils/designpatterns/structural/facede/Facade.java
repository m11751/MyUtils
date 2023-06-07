package com.aidl.myutils.designpatterns.structural.facede;

//外观类
class Facade {
    private final SystemOne systemOne;
    private final SystemTwo systemTwo;
    private final SystemThree systemThree;

    public Facade() {
        systemOne = new SystemOne();
        systemTwo = new SystemTwo();
        systemThree = new SystemThree();
    }

    public void facadeMethod() {
        System.out.println("调用外观类的facadeMethod()方法");
        systemOne.methodOne();
        systemTwo.methodTwo();
        systemThree.methodThree();
    }
}