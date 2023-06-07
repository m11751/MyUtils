package com.aidl.myutils.json;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.aidl.myutils.R;
import com.aidl.myutils.reflect.ReflectUtils;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class JsonTest extends AppCompatActivity {
    private static final String TAG = "JsonTest:evan";
    @SuppressLint("StaticFieldLeak")
    static Context context ;

    public static void setContext(Context context) {
        JsonTest.context = context;
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.i("evan","test1---------");
        json485();
    }

    /**
     * 拷贝对象实例
     */
    public static void copyTest(){
        /**
         *  public List<String> knxAddress = new ArrayList<>();  //knx地址
         *     public int dataType;     //knx数据类型
         *     public int dataLength;  //knx数据长度
         *     public int rs485port;   //485端口号
         *     public int rs485Address; //485从机地址
         *     public int rs485DeviceIndex;    //设备编号
         *     public String type;    //命令的功能类型
         *     public int operation=-1;     //knx操作类型 读还是写
         *     public String value;        //值
         *     public String exp;     //预留参数
         *     public String protocolType;
         *     //    evan add,rs485config2 新增字段:["1","2","3"]
         *     public List<String> dataValueList;
         */

        RS485DeviceFunction function = new RS485DeviceFunction();

        function.id = 1;
        function.knxAddress.add("1/1/1");
        function.dataType = 1;
        function.dataLength = 2;
        function.rs485port = 1;
        function.rs485Address = 2;
        function.rs485DeviceIndex = 3;
        function.type = "Test";
        function.operation = 0; // You can set the operation to any value you want, as it has a default value of -1
        function.value = "Hello";
        function.exp = "World";
        function.protocolType = "Modbus";
        function.dataValueList = new ArrayList<>();
        function.dataValueList.add("1");
        function.dataValueList.add("2");
        function.dataValueList.add("3");

        RS485DeviceFunction copiedFunction = new RS485DeviceFunction(function);
        copiedFunction.setValue("new value");
        Log.i("xwg","function------------------------------");
        ReflectUtils.reflect(function,"xwg");
        Log.i("xwg","copiedFunction------------------------------");
        ReflectUtils.reflect(copiedFunction,"xwg");
    }

    public  void json485(){
        // 获取应用程序上下文

        try {
            Log.i("evan","test2---------");
            InputStream inputStream = JsonTest.this.getAssets().open("device_test.json");
            Log.i("evan","test3---------");
            // 将 InputStream 转换为 BufferedReader
            BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
            // 将 JSON 文件中的内容读取为字符串
            String jsonString = br.lines().reduce("", (acc, line) -> acc + line);
            //            gson解析
            Gson gson = new Gson();
//            ObjectBean objectBean = gson.fromJson(jsonString,ObjectBean.class);
            ObjectBean ob2 = fromJson(jsonString);

//            base节点测试
//            Log.i(TAG, "第1层:\n");
//            UtilsEvan.reflect(ob2,TAG);
//
            Log.i(TAG, "第2层:\n");
            ReflectUtils.reflect(ob2.getGatewaySetting(),TAG);
//
//            Log.i(TAG, "第3层deviceType:\n");
//            UtilsEvan.reflect(ob2.getLayout().getDeviceType(),TAG);
//            Log.i(TAG, "第3层location:\n");
//            UtilsEvan.reflect(ob2.getLayout().getLocation(),TAG);
//            Log.i(TAG, "第3层smartType:\n");
//            UtilsEvan.reflect(ob2.getLayout().getSmartType(),TAG);
//
//            Log.i(TAG, "第4层deviceList:\n");
//            UtilsEvan.reflect(ob2.getLayout().getDeviceType().getDeviceList().get(0),TAG);
//
//            Log.i(TAG, "第4层typeList:\n");
//            UtilsEvan.reflect(ob2.getLayout().getDeviceType().getTypeList().get(0),TAG);


//            base节点测试
//            Log.i(TAG, "第1层:\n");
//            UtilsEvan.reflect(ob2,TAG);
//
//            Log.i(TAG, "第2层:\n");
//            UtilsEvan.reflect(ob2.getBase().getDeviceList().get(0),TAG);
//
//            Log.i(TAG, "第3层:\n");
//            UtilsEvan.reflect(ob2.getBase().getDeviceList().get(0).getFunctionList().get(0),TAG);
//
//            Log.i(TAG, "第4层feedbackList:\n");
//            UtilsEvan.reflect(ob2.getBase().getDeviceList().get(0).getFunctionList().get(0).getFeedbackList().get(0),TAG);
//
//            Log.i(TAG, "第4层sendList:\n");
//            UtilsEvan.reflect(ob2.getBase().getDeviceList().get(0).getFunctionList().get(0).getSendList().get(0),TAG);
//
//            Log.i(TAG, "第5层dataValueList:\n");
//            UtilsEvan.reflect(ob2.getBase().getDeviceList().get(0).getFunctionList().get(0).getFeedbackList().get(0).getDataValueList().get(0),TAG);


//gatewaySetting测试:第1层
//            Log.i(TAG, "第1层:\n");
//            UtilsEvan.reflect(ob2,TAG);
//            //第2层
//            Log.i(TAG, "第2层:\n");
//            UtilsEvan.reflect(ob2.getGatewaySetting(),TAG);


            //第3层
//            Log.i(TAG, "第3层:\n");
//            UtilsEvan.reflect(ob2.getGatewaySetting().getRS485PortConfig2().get(0),TAG);
////            //第4层
//            Log.i(TAG, "第4层:\n");
//            UtilsEvan.reflect(ob2.getGatewaySetting().getRS485PortConfig2().get(0).getRS485DeviceList().get(0),TAG);
//////            //第5层
//            Log.i(TAG, "第5层:\n");
//            UtilsEvan.reflect(ob2.getGatewaySetting().getRS485PortConfig2().get(0).getRS485DeviceList().get(0).getFunctionList().get(0),TAG);
////            //第6层
//            Log.i(TAG, "第6层:\n");
//            UtilsEvan.reflect(ob2.getGatewaySetting().getRS485PortConfig2().get(0).getRS485DeviceList().get(0)
//                    .getFunctionList().get(0).getSendList().get(0),TAG);
////            //第7层
//            Log.i(TAG, "第7层:\n");
//            UtilsEvan.reflect(ob2.getGatewaySetting().getRS485PortConfig2().get(0).getRS485DeviceList().get(0)
//                    .getFunctionList().get(0).getSendList().get(0).getDataLength(),TAG);

        } catch (IOException e) {
            Log.i("evan"," error ---------" + e);
            throw new RuntimeException(e);
        }
    }

    /**
     * JSON字符串中创建GatewaySettings对象。在该方法中，我们使用TypeToken类将JSON字符串转换为正确的泛型类型。
     * @param json
     * @return
     */
    public static ObjectBean fromJson(String json) {
        Gson gson = new Gson();
        Type type = new TypeToken<ObjectBean>() {}.getType();
        return gson.fromJson(json, type);
    }

    public static void main(String[] args) throws JSONException {
//        testJsonObject();
//        json485();
    }

    private static void testJsonObject() throws JSONException {
        // 构造一个JSONObject对象
        JSONObject jsonObject = new JSONObject();

        RS485DeviceFunction rs = new RS485DeviceFunction();
        rs.rs485port = 22;
        ArrayList<String> addList = new ArrayList<String>(Arrays.asList("add1", "add2", "add3"));
        rs.knxAddress =  addList;
        rs.rs485DeviceIndex = 1;
        rs.value = "value";
        rs.exp = "exp";
        rs.operation = 0;

        // 添加一些键值对
        jsonObject.put("port", rs.rs485port);

        // 将另一个JSONObject对象作为值添加进去
        JSONObject addressObject = new JSONObject();
        addressObject.put("add1", addList.get(0));
        addressObject.put("add2", addList.get(1));
        addressObject.put("add3", addList.get(2));
        jsonObject.put("add", addressObject);


        // 将JSONObject对象转换成字符串
        String jsonString = jsonObject.toString();
//        System.out.println(jsonString);
        Log.i("xwg","jsonStr:" + jsonString);

        // 解析字符串
        JSONObject newJsonObject = new JSONObject(jsonString);
        int port = newJsonObject.getInt("port");
        JSONObject jo = newJsonObject.getJSONObject("add");
        String s1 = jo.getString("add1");
        String s2 = jo.getString("add2");

        Log.i("xwg","port:" + port);
        Log.i("xwg","s1:" + s1);
        Log.i("xwg","s2:" + s2);
    }
}
