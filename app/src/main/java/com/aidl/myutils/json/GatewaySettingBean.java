package com.aidl.myutils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * gatewaySetting节点,第2层,配置表使用11个参数
 * 在使用 Gson 解析 JSON 数据时，字段的大小写需要完全匹配，包括字段名和类属性名的大小写。
 *
 * 如果 JSON 数据中的字段名和类属性名不一致，可以使用注解来指定它们之间的对应关系。例如，使用 @SerializedName 注解来指定 JSON 数据中的字段名和类属性名的对应关系。例如：
 *
 * public class MyBean {
 *     @SerializedName("field_name_in_json")
 *     private String fieldNameInClass;
 *
 *     // getter and setter
 * }
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class GatewaySettingBean {


    List<RS485PortCongfig2Bean> RS485PortConfig2; //RS485PortCongfig2Bean 的list集合


    public List<RS485PortCongfig2Bean> getRS485PortConfig2() {
        return RS485PortConfig2;
    }

    public void setRS485PortConfig2(List<RS485PortCongfig2Bean> RS485PortConfig2) {
        this.RS485PortConfig2 = RS485PortConfig2;
    }

    public List<RS485PortBean> getRS485Port() {
        return RS485Port;
    }

    public void setRS485Port(List<RS485PortBean> RS485Port) {
        this.RS485Port = RS485Port;
    }

    List<RS485PortBean> RS485Port; //RS485PortBean 的list集合
    String checkAddr;   //校验地址
    List<String> deviceMgmtMode;    //String 的list集合
    String devicePsw;   //设备密码


    String deviceUSer;  //设备用户
    String gatewayType; //网关类型:TTG-IP/S
    String id485;   //
    String ip;  //ip地址:192.168.1.100
    String knxSrcAddr;  //knx协议地址
    String port;    //端口号:3671

    public String getCheckAddr() {
        return checkAddr;
    }

    public void setCheckAddr(String checkAddr) {
        this.checkAddr = checkAddr;
    }

    public List<String> getDeviceMgmtMode() {
        return deviceMgmtMode;
    }

    public void setDeviceMgmtMode(List<String> deviceMgmtMode) {
        this.deviceMgmtMode = deviceMgmtMode;
    }

    public String getDevicePsw() {
        return devicePsw;
    }

    public void setDevicePsw(String devicePsw) {
        this.devicePsw = devicePsw;
    }

    public String getDeviceUSer() {
        return deviceUSer;
    }

    public void setDeviceUSer(String deviceUSer) {
        this.deviceUSer = deviceUSer;
    }

    public String getGatewayType() {
        return gatewayType;
    }

    public void setGatewayType(String gatewayType) {
        this.gatewayType = gatewayType;
    }

    public String getId485() {
        return id485;
    }

    public void setId485(String id485) {
        this.id485 = id485;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getKnxSrcAddr() {
        return knxSrcAddr;
    }

    public void setKnxSrcAddr(String knxSrcAddr) {
        this.knxSrcAddr = knxSrcAddr;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }
}
