package com.aidl.myutils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * object节点,第1层,配置表使用6个参数,@JsonIgnoreProperties(ignoreUnknown = true) 忽略未知属性
 * 总配置的顶级根目录
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ObjectBean {
//    base
    BaseBean base;

    public BaseBean getBase() {
        return base;
    }

    public void setBase(BaseBean base) {
        this.base = base;
    }

    GatewaySettingBean gatewaySetting;    //RS485LocalConfigPort类,11个参数

    public GatewaySettingBean getGatewaySetting() {
        return gatewaySetting;
    }

    public void setGatewaySetting(GatewaySettingBean gatewaySetting) {
        this.gatewaySetting = gatewaySetting;
    }

    public String getIdMax() {
        return idMax;
    }

    public void setIdMax(String idMax) {
        this.idMax = idMax;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    String idMax;   //"9626001"

   LayoutBean layout;

    public LayoutBean getLayout() {
        return layout;
    }

    public void setLayout(LayoutBean layout) {
        this.layout = layout;
    }

    //    smart,list字段
    String version; //版本:"6060"
}
