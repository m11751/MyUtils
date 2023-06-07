package com.aidl.myutils.json;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by liuweibo on 2020/9/9.
 * functionlist节点,第5层配置文件有效字段6个
 */

public class FunctionListBean {

    public String id;  //功能id:"901"

    public String name; //功能名称:"开关"

    public String ext; //预留参数:

//    sendList
    public List<SendListBean> sendList;
//    feedbackList
    public List<FeedbackListBean> feedbackList;

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

    public String getExt() {
        return ext;
    }

    public void setExt(String ext) {
        this.ext = ext;
    }

    public List<SendListBean> getSendList() {
        return sendList;
    }

    public void setSendList(List<SendListBean> sendList) {
        this.sendList = sendList;
    }

    public List<FeedbackListBean> getFeedbackList() {
        return feedbackList;
    }

    public void setFeedbackList(List<FeedbackListBean> feedbackList) {
        this.feedbackList = feedbackList;
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

    //knx地址
    public List<String> knxAddress = new ArrayList<>();

    //knx数据类型
    public int dataType;

    //knx数据长度
    public int dataLength;

    //485端口号
    public int rs485port;

    //485从机地址
    public int rs485Address;

    //设备编号
    public int rs485DeviceIndex;

    //功能类型:"switch"
    public String type;

    //knx操作类型 读还是写
    public int operation=-1;

    //值
    public String value;

    //预留参数
    public String exp;

    public String protocolType;

}
