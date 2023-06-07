package com.aidl.myutils.designpatterns.structural.bridge;

public class RedColor implements Color {
    @Override
    public void fill() {
        System.out.println("Fill with red color.");
    }
}
