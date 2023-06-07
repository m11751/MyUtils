package com.aidl.myutils.designpatterns.structural.bridge;


public class Rectangle implements Shape {
    private Color color;
    public Rectangle(Color color) {
        this.color = color;
    }
    @Override
    public void draw() {
        System.out.print("Draw a rectangle, ");
        color.fill();
    }
}
