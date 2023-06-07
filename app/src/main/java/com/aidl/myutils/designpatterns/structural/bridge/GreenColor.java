package com.aidl.myutils.designpatterns.structural.bridge;

public class GreenColor implements Color {
    @Override
    public void fill() {
        System.out.println("Fill with green color.");
    }
}

