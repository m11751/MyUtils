package com.aidl.myutils.designpatterns.simple.factory;

public class OperationFactory {
   public static Operation createOperation(String operation){
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
