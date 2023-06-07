package com.aidl.myutils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Created by liuweibo on 2020/9/9.
 * RS485DeviceList 第4层节点,配置文件有效8字段,2023.3.21 evan modify
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RS485DeviceListBean {
    public String id;  //设备id:"9"

    public String subType;  //子类型:"1"

    public String deviceModel;  //设备型号名称:"WRC100GC"

    public String deviceAddress;    //设备地址: "0-19"

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSubType() {
        return subType;
    }

    public void setSubType(String subType) {
        this.subType = subType;
    }

    public String getDeviceModel() {
        return deviceModel;
    }

    public void setDeviceModel(String deviceModel) {
        this.deviceModel = deviceModel;
    }

    public String getDeviceAddress() {
        return deviceAddress;
    }

    public void setDeviceAddress(String deviceAddress) {
        this.deviceAddress = deviceAddress;
    }

    public String getExt() {
        return ext;
    }

    public void setExt(String ext) {
        this.ext = ext;
    }

    public String getDevId() {
        return devId;
    }

    public void setDevId(String devId) {
        this.devId = devId;
    }

    public int getRs485port() {
        return rs485port;
    }

    public void setRs485port(int rs485port) {
        this.rs485port = rs485port;
    }

    public int getRs485Address() {
        return rs485Address;
    }

    public void setRs485Address(int rs485Address) {
        this.rs485Address = rs485Address;
    }

    public int getRs485DeviceIndex() {
        return rs485DeviceIndex;
    }

    public void setRs485DeviceIndex(int rs485DeviceIndex) {
        this.rs485DeviceIndex = rs485DeviceIndex;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getExp() {
        return exp;
    }

    public void setExp(String exp) {
        this.exp = exp;
    }

    public String ext;  //预留参数

    public String devId;
    //485端口号
    public int rs485port;

    //485从机地址
    public int rs485Address;

    //设备编号
    public int rs485DeviceIndex;

    //设备类型:AC
    public String type;

    //设备名称:研发办公区3
    public String name;

    //预留参数
    public String exp;


    public List<FunctionListBean> getFunctionList() {
        return functionList;
    }

    public void setFunctionList(List<FunctionListBean> functionList) {
        this.functionList = functionList;
    }

    //功能列表
    public List<FunctionListBean> functionList;

}
