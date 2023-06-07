package com.aidl.myutils.designpatterns.simple.factory;

public class Subtraction extends Operation{
    @Override
    public double getResult(double numA, double numB) {
        return numA - numB;
    }
}
