package com.aidl.myutils.json;

import java.util.List;

/**
 * sendlist节点,第6层,config中只用到5个
 */
public class SendListBean {
    public String addr; //地址:"12/1/20"
    public String protocolType; //端口类型:"KNK"
    public String sleep;
    public String dataType; //数据类型:"0"
    public String dataLength;   //数据长度: "0"
    public List<String> dataValueList;  //数据值List

    public String getAddr() {
        return addr;
    }

    public void setAddr(String addr) {
        this.addr = addr;
    }

    public String getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(String protocolType) {
        this.protocolType = protocolType;
    }

    public String getSleep() {
        return sleep;
    }

    public void setSleep(String sleep) {
        this.sleep = sleep;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public String getDataLength() {
        return dataLength;
    }

    public void setDataLength(String dataLength) {
        this.dataLength = dataLength;
    }

    public List<String> getDataValueList() {
        return dataValueList;
    }

    public void setDataValueList(List<String> dataValueList) {
        this.dataValueList = dataValueList;
    }
}
