package com.aidl.myutils.designpatterns.structural.decorator;

public class Rectangle implements Shape {
    @Override
    public void draw() {
        System.out.println("Draw a rectangle");
    }
}
