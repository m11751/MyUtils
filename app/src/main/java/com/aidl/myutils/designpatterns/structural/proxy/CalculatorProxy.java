package com.aidl.myutils.designpatterns.structural.proxy;

public class CalculatorProxy implements Calculator {
    private Calculator calculator;

    public CalculatorProxy(Calculator calculator) {
        this.calculator = calculator;
    }

    @Override
    public int add(int a, int b) {
        System.out.println("Before add method");
        int result = calculator.add(a, b);
        System.out.println("After add method");
        return result;
    }
}

