package com.aidl.myutils.json;

import java.util.List;

public class DeviceListBean {
    String area;    //"2"
    String floor;   //"1"
    String layout;
//    floorList
    List<TypeListBean>floorList;

    public List<TypeListBean> getFloorList() {
        return floorList;
    }

    public void setFloorList(List<TypeListBean> floorList) {
        this.floorList = floorList;
    }

    public String getLayout() {
        return layout;
    }

    public void setLayout(String layout) {
        this.layout = layout;
    }

    public String getArea() {
        return area;
    }

    public void setArea(String area) {
        this.area = area;
    }

    public String getFloor() {
        return floor;
    }

    public void setFloor(String floor) {
        this.floor = floor;
    }

    public List<FunctionListBean> getFunctionList() {
        return functionList;
    }

    public void setFunctionList(List<FunctionListBean> functionList) {
        this.functionList = functionList;
    }

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSubType() {
        return subType;
    }

    public void setSubType(String subType) {
        this.subType = subType;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    //    functionlist  //
    List<FunctionListBean> functionList;
    String icon;    //"icon_ac_01"
    String id;  //"72"
    String name;    //"空调"
    String subType; //"1"
    String type;    //"AC"
}
