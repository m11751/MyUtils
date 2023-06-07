package com.aidl.myutils.numberbase;

/**
 * Created by liuweibo on 2020/9/14.
 * 16进制转2进制工具类
 */

public class Hex2Byte {
    /**
     * 将一个byte数组转换成对应的十六进制字符串表示形式的功能
     * @param bytes  { 0x12, 0x34, (byte)0xAB, (byte)0xCD };
     * @param length 4;
     * @return 1234abcd
     */
    public static String bytesToHex(byte[] bytes,int length) {
        if (bytes == null){
            return "";
        }
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     *  将整个字节数组都转换成对应的十六进制字符串
     * @param bytes { 0x12, 0x34, (byte)0xAB, (byte)0xCD }
     * @return 1234abcd
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null){
            return "";
        }
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     *将一个 byte 类型的数据转换成对应的两位十六进制字符串的功能
     * @param data  (byte)0xAB
     * @return  ab
     */
    public static String byteToHex(byte data) {
        StringBuffer sb = new StringBuffer();
        String hex = Integer.toHexString(data & 0xFF);
        if(hex.length() < 2){
            sb.append(0);
        }
        sb.append(hex);
        return sb.toString();
    }

    /**
     * 这是一个将16进制字符串转换为byte数组的方法。具体来说，它将输入的16进制字符串按照两个字符一组，
     * 将每组转换为一个byte，并将所有的byte组成一个byte数组作为输出。
     * @param hex A5B2C3D4
     * @return [-91, -78, -61, -44]
     */
    public static  byte[] hexToByteArray(String hex){
        int hexlen = hex.length();
        byte[] result;
        if (hexlen % 2 == 1){
            //奇数
            hexlen++;
            result = new byte[(hexlen/2)];
            hex="0"+hex;
        }else {
            //偶数
            result = new byte[(hexlen/2)];
        }
        int j=0;
        for (int i = 0; i < hexlen; i+=2){
            result[j]=hexToByte(hex.substring(i,i+2));
            j++;
        }
        return result;
    }

    /** 将十六进制字符串 "ab" 转换为对应的 byte 类型数据
     * @param hex "ab"
     * @return  -85
     */
    public static  byte hexToByte(String hex){
        return (byte)Integer.parseInt(hex,16);
    }

}
