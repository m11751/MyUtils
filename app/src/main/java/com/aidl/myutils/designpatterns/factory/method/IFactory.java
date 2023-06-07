package com.aidl.myutils.designpatterns.factory.method;

import com.aidl.myutils.designpatterns.simple.factory.Operation;

/**
 * 工厂接口
 */
public interface IFactory {
    public Operation createOperation(String operType);
}
