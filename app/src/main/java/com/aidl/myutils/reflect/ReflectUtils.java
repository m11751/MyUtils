package com.aidl.myutils.reflect;

import android.util.Log;

import java.lang.reflect.Field;

/**
 * evan add,反射相关工具类
 */
public class ReflectUtils {
    public final static String TOTAL_DEVICE_TYPE_AC = "AC"; //总类型:空调
    public final static String TOTAL_DEVICE_TYPE_LIGHT = "light"; //总类型:灯
    public final static String TOTAL_DEVICE_TYPE_CURTAIN = "curtain"; //总类型:窗帘

    public final static String SUB_DEVICE_TYPE_AC_0 = "0"; //子类型:风机盘管
    public final static String SUB_DEVICE_TYPE_AC_1 = "1"; //子类型:VRV空调
    public final static String SUB_DEVICE_TYPE_LIGHT_0 = "0"; //子类型:开关灯
    public final static String SUB_DEVICE_TYPE_LIGHT_1 = "1"; //子类型:调光灯
    public final static String SUB_DEVICE_TYPE_CURTAIN_0 = "0"; //子类型:卷帘
    public final static String SUB_DEVICE_TYPE_CURTAIN_1 = "1"; //子类型:布/纱帘

    public final static String FUNCTION_TYPE_TYPE_SWITCH = "switch"; //开或关
    public final static String FUNCTION_TYPE_TYPE_SPEED = "speed"; //风速
    public final static String FUNCTION_TYPE_TYPE_MODE = "mode"; //模式
    public final static String FUNCTION_TYPE_TYPE_TARGET_TEMP = "targetTemp"; //目标温度
    public final static String FUNCTION_TYPE_TYPE_TEMP_SENSOR = "tempSensor"; //传感器温度
    /**
     * 通过反射打印对象的所有字段信息
     * @param o 对象
     * @param tag   tag关键字
     */
    public static void reflect(Object o, String tag){
        //获取参数类
        Class<?> cls = o.getClass();
        //将参数类转换为对应属性数量的Field类型数组（即该类有多少个属性字段 N 转换后的数组长度即为 N）
        Field[] fields = cls.getDeclaredFields();
        for (Field f : fields) {
            f.setAccessible(true);
            try {
                Log.i(tag, "属性名：" + f.getName() + "；属性值：" + f.get(o) + ";字段类型：" + f.getGenericType());
            } catch (IllegalArgumentException | IllegalAccessException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                Log.i(tag, "ReflectUtil error:" + e);
            }
        }
    }//end reflect
}
