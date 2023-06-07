package com.aidl.myutils.json;

import java.util.List;

/**
 * layout节点第二层
 */
public class DeviceTypeBean {
    List<DeviceListBean> deviceList;
    String icon;    //"logo.png"
    String id;  //"1111"
    String name;    //"设备"

    public List<DeviceListBean> getDeviceList() {
        return deviceList;
    }

    public void setDeviceList(List<DeviceListBean> deviceList) {
        this.deviceList = deviceList;
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

    public List<DeviceListBean> getTypeList() {
        return typeList;
    }

    public void setTypeList(List<DeviceListBean> typeList) {
        this.typeList = typeList;
    }

    //    String typeList
    List<DeviceListBean> typeList;
}
