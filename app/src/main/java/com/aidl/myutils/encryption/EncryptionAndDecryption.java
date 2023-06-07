package com.aidl.myutils.encryption;

import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 加密解密算法
 */
public class EncryptionAndDecryption {
    /**
     * 由于哈希算法不是可逆的，因此无法将SHA-2哈希值解密回原始密码。
     *
     * 通常，您可以使用哈希算法对用户输入的密码进行加密，然后将其与存储在数据库中的加密密码进行比较以进行身份验证。
     * @param password  source string
     * @return sha256 string
     */
    private static String getSHA256(String password){

        try {
            // 创建SHA-2加密实例
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // 将密码转换为字节数组并加密
            byte[] hashedPassword = md.digest(password.getBytes());

            // 将加密后的密码转换为16进制字符串
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedPassword) {
                sb.append(String.format("%02x", b));
            }
            System.out.println("Hashed Password: " + sb.toString());
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return password;
        }
    }

    /**
     * md5加密
     * @param message   需要加密的字符串
     * @return  加密后的字符串
     */
    public static String getMD5(String message) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(message.getBytes());
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                String hex = Integer.toHexString(b & 0xff);
                if (hex.length() == 1) {
                    result.append("0");
                }
                result.append(hex);
            }
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * base64解密
     * @param pws   base64的加密字符串
     * @return  string类型的原始数据
     */
    private static String getBase64(String pws){
        byte[] decoded = Base64.getDecoder().decode(pws);
        return new String(decoded);
    }

    public static void main(String[] args) {
        Log.i("xwg","code is " + getBase64("eWFubXVtdW11bXU="));
//        Log.i("xwg","yanmumumumu with md5 is:" + getMD5("yanmumumumu"));
//        Log.i("xwg","yanmumumumu with sha256 is:" + getSHA256("yanmumumumu"));
    }
}
