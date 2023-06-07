package com.aidl.myutils.designpatterns.factory.method;

import com.aidl.myutils.designpatterns.simple.factory.Addition;
import com.aidl.myutils.designpatterns.simple.factory.Division;
import com.aidl.myutils.designpatterns.simple.factory.IndexCompute;
import com.aidl.myutils.designpatterns.simple.factory.Multiplication;
import com.aidl.myutils.designpatterns.simple.factory.Operation;
import com.aidl.myutils.designpatterns.simple.factory.Subtraction;

/**
 * 工厂方法模式
 */
public class OperationFactory {
   public static Operation createOperation(String operation){
      Operation op = null;
      IFactory factory = null;
      switch (operation){
         case "+":
         case "-":
         case "*":
         case "/": factory = new FactoryBasic();break;
         case "pow":
         case "log": factory = new FactoryAdvanced();break;
      }
      assert factory != null;
      op = factory.createOperation(operation);
      return op;
   }
}
