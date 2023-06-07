package com.aidl.myutils.designpatterns.simple.factory;

import android.util.Log;

public class Division extends Operation{
    private static final String TAG = "Division:xwg";
    @Override
    public double getResult(double numA, double numB) {
        if (numB == 0){
            Log.i(TAG,"除数不能为0！");
            throw new ArithmeticException();
        }
        return numA / numB;
    }
}
