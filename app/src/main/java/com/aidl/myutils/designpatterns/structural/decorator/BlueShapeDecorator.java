package com.aidl.myutils.designpatterns.structural.decorator;

public class BlueShapeDecorator extends ShapeDecorator {
    public BlueShapeDecorator(Shape shape) {
        super(shape);
    }

    @Override
    public void draw() {
        shape.draw();
        setBlueBorder(shape);
    }

    private void setBlueBorder(Shape shape){
        System.out.println("Border Color: Blue");
    }
}