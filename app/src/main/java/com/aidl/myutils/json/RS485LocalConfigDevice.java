package com.aidl.myutils.json;

import java.util.List;

/**
 *
 */
public class RS485LocalConfigDevice {
    public String id;   //"13"
    public String name; //"林总办公室"
    public String deviceAddress;    //"0-15"
    public String deviceModle;  //"WRC100GC"
    public String deviceType;   //"0"
    public String ext;
    public List<ValueBean> onOffFeedback;   //开关反馈
    public List<ValueBean> tempFeedback;    //温度反馈
    public List<ValueBean> modeFeedback;    //模式反馈
    public List<ValueBean> speedFeedback;   //速度反馈
    public List<ValueBean> tempSensorFeedback;
    public List<ValueBean> onOff;   //开关
    public List<ValueBean> targetTemp;  //目标温度
    public List<ValueBean> speed;   //速度
    public List<ValueBean> mode;    //模式

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

    public String getDeviceAddress() {
        return deviceAddress;
    }

    public void setDeviceAddress(String deviceAddress) {
        this.deviceAddress = deviceAddress;
    }

    public String getDeviceModle() {
        return deviceModle;
    }

    public void setDeviceModle(String deviceModle) {
        this.deviceModle = deviceModle;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public String getExt() {
        return ext;
    }

    public void setExt(String ext) {
        this.ext = ext;
    }

    public List<ValueBean> getOnOffFeedback() {
        return onOffFeedback;
    }

    public void setOnOffFeedback(List<ValueBean> onOffFeedback) {
        this.onOffFeedback = onOffFeedback;
    }

    public List<ValueBean> getTempFeedback() {
        return tempFeedback;
    }

    public void setTempFeedback(List<ValueBean> tempFeedback) {
        this.tempFeedback = tempFeedback;
    }

    public List<ValueBean> getHumidityFeedback() {
        return HumidityFeedback;
    }

    public void setHumidityFeedback(List<ValueBean> humidityFeedback) {
        HumidityFeedback = humidityFeedback;
    }

    public List<ValueBean> getVOCFeedback() {
        return VOCFeedback;
    }

    public void setVOCFeedback(List<ValueBean> VOCFeedback) {
        this.VOCFeedback = VOCFeedback;
    }

    public List<ValueBean> getCO2Feedback() {
        return CO2Feedback;
    }

    public void setCO2Feedback(List<ValueBean> CO2Feedback) {
        this.CO2Feedback = CO2Feedback;
    }

    public List<ValueBean> getPM25Feedback() {
        return PM25Feedback;
    }

    public void setPM25Feedback(List<ValueBean> PM25Feedback) {
        this.PM25Feedback = PM25Feedback;
    }

    public List<ValueBean> getModeFeedback() {
        return modeFeedback;
    }

    public void setModeFeedback(List<ValueBean> modeFeedback) {
        this.modeFeedback = modeFeedback;
    }

    public List<ValueBean> getSpeedFeedback() {
        return speedFeedback;
    }

    public void setSpeedFeedback(List<ValueBean> speedFeedback) {
        this.speedFeedback = speedFeedback;
    }

    public List<ValueBean> getTempSensorFeedback() {
        return tempSensorFeedback;
    }

    public void setTempSensorFeedback(List<ValueBean> tempSensorFeedback) {
        this.tempSensorFeedback = tempSensorFeedback;
    }

    public List<ValueBean> getOnOff() {
        return onOff;
    }

    public void setOnOff(List<ValueBean> onOff) {
        this.onOff = onOff;
    }

    public List<ValueBean> getTargetTemp() {
        return targetTemp;
    }

    public void setTargetTemp(List<ValueBean> targetTemp) {
        this.targetTemp = targetTemp;
    }

    public List<ValueBean> getSpeed() {
        return speed;
    }

    public void setSpeed(List<ValueBean> speed) {
        this.speed = speed;
    }

    public List<ValueBean> getMode() {
        return mode;
    }

    public void setMode(List<ValueBean> mode) {
        this.mode = mode;
    }

    public List<ValueBean> getStop() {
        return stop;
    }

    public void setStop(List<ValueBean> stop) {
        this.stop = stop;
    }

    public List<ValueBean> getCourse() {
        return course;
    }

    public void setCourse(List<ValueBean> course) {
        this.course = course;
    }

    public List<ValueBean> getCourseFeedback() {
        return courseFeedback;
    }

    public void setCourseFeedback(List<ValueBean> courseFeedback) {
        this.courseFeedback = courseFeedback;
    }

    public List<ValueBean> stop;
    public List<ValueBean> course;
    public List<ValueBean> courseFeedback;
    public List<ValueBean> TempFeedback;
    public List<ValueBean> HumidityFeedback;
    public List<ValueBean> VOCFeedback;
    public List<ValueBean> CO2Feedback;
    public List<ValueBean> PM25Feedback;
}
