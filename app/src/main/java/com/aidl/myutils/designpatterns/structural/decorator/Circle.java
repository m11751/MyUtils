package com.aidl.myutils.designpatterns.structural.decorator;

public class Circle implements Shape {
    @Override
    public void draw() {
        System.out.println("Drawing a Circle.");
    }
}