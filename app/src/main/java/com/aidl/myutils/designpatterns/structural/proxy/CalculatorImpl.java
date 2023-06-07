package com.aidl.myutils.designpatterns.structural.proxy;

public class CalculatorImpl implements Calculator {
    @Override
    public int add(int a, int b) {
        return a + b;
    }
}

