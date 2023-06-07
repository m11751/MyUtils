package com.aidl.myutils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * RS485PortCongfi2 第3层节点,配置文件有效15字段
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RS485PortCongfig2Bean {
    String id;  //设备id:"8"
    String name;    //设备中文名称:"开利空调"
    String portId;  //端口号:"0"
    String portNode;    //挂载节点: "/dev/ttyS0"
    String deviceType;  //设备类型代码:"AC"
    String deviceSubType;   //设备子类型代码:"1"
    String deviceModel; //设备型号英文名称:"WRC100GC"

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

    public String getPortId() {
        return portId;
    }

    public void setPortId(String portId) {
        this.portId = portId;
    }

    public String getPortNode() {
        return portNode;
    }

    public void setPortNode(String portNode) {
        this.portNode = portNode;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public String getDeviceSubType() {
        return deviceSubType;
    }

    public void setDeviceSubType(String deviceSubType) {
        this.deviceSubType = deviceSubType;
    }

    public String getDeviceModel() {
        return deviceModel;
    }

    public void setDeviceModel(String deviceModel) {
        this.deviceModel = deviceModel;
    }

    public String getGatewayType() {
        return gatewayType;
    }

    public void setGatewayType(String gatewayType) {
        this.gatewayType = gatewayType;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getAppIcon() {
        return appIcon;
    }

    public void setAppIcon(String appIcon) {
        this.appIcon = appIcon;
    }



    public String getAppDesciption() {
        return appDesciption;
    }

    public void setAppDesciption(String appDesciption) {
        this.appDesciption = appDesciption;
    }

    public String getURL() {
        return URL;
    }

    public void setURL(String URL) {
        this.URL = URL;
    }

    public String getExt() {
        return ext;
    }

    public void setExt(String ext) {
        this.ext = ext;
    }

    String gatewayType; //网关设置型号名称:GW-EK5-N01
    String appName; //app名称:开利485
    String appIcon; //app图标

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    String packageName; //包名:com.ttg.rs485.kaili
    String appDesciption;   //app描述
    String URL; //URL地址
    String ext; //扩展备注

    public List<RS485DeviceListBean> getRS485DeviceList() {
        return RS485DeviceList;
    }

    public void setRS485DeviceList(List<RS485DeviceListBean> RS485DeviceList) {
        this.RS485DeviceList = RS485DeviceList;
    }

    //    RS485DeviceList
    List<RS485DeviceListBean> RS485DeviceList;
}
