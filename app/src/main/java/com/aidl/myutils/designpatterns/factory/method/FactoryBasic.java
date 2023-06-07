package com.aidl.myutils.designpatterns.factory.method;

import com.aidl.myutils.designpatterns.simple.factory.Addition;
import com.aidl.myutils.designpatterns.simple.factory.Division;
import com.aidl.myutils.designpatterns.simple.factory.IndexCompute;
import com.aidl.myutils.designpatterns.simple.factory.Multiplication;
import com.aidl.myutils.designpatterns.simple.factory.Operation;
import com.aidl.myutils.designpatterns.simple.factory.Subtraction;

/**
 * 基本运算工厂类
 */
public class FactoryBasic implements IFactory {
    public Operation createOperation(String operation) {
        Operation op = null;
        switch (operation){
            case "+": op = new Addition();break;
            case "-": op = new Subtraction();break;
            case "*": op = new Multiplication();break;
            case "/": op = new Division();break;
            case "^": op = new IndexCompute();break;
        }
        return op;
    }

}
