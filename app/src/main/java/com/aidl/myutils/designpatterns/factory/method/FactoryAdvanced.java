package com.aidl.myutils.designpatterns.factory.method;

import com.aidl.myutils.designpatterns.simple.factory.Addition;
import com.aidl.myutils.designpatterns.simple.factory.Division;
import com.aidl.myutils.designpatterns.simple.factory.IndexCompute;
import com.aidl.myutils.designpatterns.simple.factory.Multiplication;
import com.aidl.myutils.designpatterns.simple.factory.Operation;
import com.aidl.myutils.designpatterns.simple.factory.Subtraction;

/**
 * 高级运算工厂类
 */
public class FactoryAdvanced implements IFactory {
    public Operation createOperation(String operation) {
        Operation op = null;
        switch (operation){
            case "pow": op = new Pow();break;
            case "log": op = new Log();break;
//            此处可以继续添加新的运算方法
        }
        return op;
    }

}
