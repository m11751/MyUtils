package com.aidl.myutils.designpatterns.factory.method;

import com.aidl.myutils.designpatterns.simple.factory.Operation;

/**
 * 对数预算
 */
public class Log extends Operation {
    @Override
    public double getResult(double numA, double numB) {
//        直接运输缺少判断
        return Math.log(numB)/Math.log(numA);
    }
}
