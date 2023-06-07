package com.aidl.myutils.json;

import java.util.List;

public class BaseBean {
    public List<DeviceListBean> getDeviceList() {
        return deviceList;
    }

    public void setDeviceList(List<DeviceListBean> deviceList) {
        this.deviceList = deviceList;
    }

    List<DeviceListBean> deviceList;
}
