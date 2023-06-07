package com.aidl.myutils.designpatterns.factory.method;

import com.aidl.myutils.designpatterns.simple.factory.Operation;

/**
 * 指数预算
 */
public class Pow extends Operation {
    @Override
    public double getResult(double numA, double numB) {
//        直接运输缺少判断
        return Math.pow(numA,numB);
    }
}
