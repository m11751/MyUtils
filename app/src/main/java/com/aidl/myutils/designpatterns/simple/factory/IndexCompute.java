package com.aidl.myutils.designpatterns.simple.factory;

/**
 * 指数计算
 */
public class IndexCompute extends Operation{
    @Override
    public double getResult(double numA, double numB) {
        double result = 1.0;
        int exponent = (int)numB;
        // 处理指数为正数的情况
        if (exponent >= 0) {
            for (int i = 0; i < exponent; i++) {
                result *= numA;
            }
        }
        // 处理指数为负数的情况
        else {
            for (int i = 0; i > exponent; i--) {
                result /= numA;
            }
        }

        return result;
    }
}
