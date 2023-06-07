package com.aidl.myutils.json;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by liuweibo on 2020/9/9.
 * 命令的类,保持每一条命令需要的信息，自定义的function类
 */

public class RS485DeviceFunction {
    public int id;
    public List<String> knxAddress = new ArrayList<>();  //knx地址
    public int dataType;     //knx数据类型
    public int dataLength;  //knx数据长度
    public int rs485port;   //485端口号

    public RS485DeviceFunction(RS485DeviceFunction other) {
        this.id = other.id;
        this.knxAddress = new ArrayList<>(other.knxAddress);
        this.dataType = other.dataType;
        this.dataLength = other.dataLength;
        this.rs485port = other.rs485port;
        this.rs485Address = other.rs485Address;
        this.rs485DeviceIndex = other.rs485DeviceIndex;
        this.type = other.type;
        this.operation = other.operation;
        this.value = other.value;
        this.exp = other.exp;
        this.protocolType = other.protocolType;
        this.dataValueList = new ArrayList<>(other.dataValueList);
    }

    public RS485DeviceFunction() {

    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public List<String> getKnxAddress() {
        return knxAddress;
    }

    public void setKnxAddress(List<String> knxAddress) {
        this.knxAddress = knxAddress;
    }

    public int getDataType() {
        return dataType;
    }

    public void setDataType(int dataType) {
        this.dataType = dataType;
    }

    public int getDataLength() {
        return dataLength;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = dataLength;
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

    public int getOperation() {
        return operation;
    }

    public void setOperation(int operation) {
        this.operation = operation;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getExp() {
        return exp;
    }

    public void setExp(String exp) {
        this.exp = exp;
    }

    public String getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(String protocolType) {
        this.protocolType = protocolType;
    }

    public List<String> getDataValueList() {
        return dataValueList;
    }

    public void setDataValueList(List<String> dataValueList) {
        this.dataValueList = dataValueList;
    }

    public int rs485Address; //485从机地址
    public int rs485DeviceIndex;    //设备编号
    public String type;    //命令的功能类型
    public int operation=-1;     //knx操作类型 读还是写
    public String value;        //值
    public String exp;     //预留参数
    public String protocolType;
    //    evan add,rs485config2 新增字段:["1","2","3"]
    public List<String> dataValueList;
}
