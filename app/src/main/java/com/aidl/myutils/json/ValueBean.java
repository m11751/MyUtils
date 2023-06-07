package com.aidl.myutils.json;

/**
 * mode字段里的值
 */
public class ValueBean {
    public String addr; //"12/2/15"
    public String dataType; //"7"
    public String dataLength;   //"0"
    public String protocolType = "KNX"; //"KNX",ProtocolType.PROTOCOL_KNX

    public String getAddr() {
        return addr;
    }

    public void setAddr(String addr) {
        this.addr = addr;
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

    public String getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(String protocolType) {
        this.protocolType = protocolType;
    }
}
