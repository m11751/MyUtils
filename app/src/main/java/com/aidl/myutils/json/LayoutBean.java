package com.aidl.myutils.json;

public class LayoutBean {
    //deviceType list
    DeviceTypeBean deviceType;

    public DeviceTypeBean getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(DeviceTypeBean deviceType) {
        this.deviceType = deviceType;
    }

    String lang;
    //location list
    DeviceListBean location;
    String projectBackground;

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public DeviceListBean getLocation() {
        return location;
    }

    public void setLocation(DeviceListBean location) {
        this.location = location;
    }

    public String getProjectBackground() {
        return projectBackground;
    }

    public void setProjectBackground(String projectBackground) {
        this.projectBackground = projectBackground;
    }

    public DeviceListBean getSmartType() {
        return smartType;
    }

    public void setSmartType(DeviceListBean smartType) {
        this.smartType = smartType;
    }

    //smartType list
    DeviceListBean smartType;
}
