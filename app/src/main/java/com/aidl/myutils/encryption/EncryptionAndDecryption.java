package com.aidl.myutils.encryption;

import android.util.Log;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 加密解密算法
 */
public class EncryptionAndDecryption {
    private static final String TAG = "EncryptionAndDecryption:xwg";
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
     * MD5是不可逆的，因此解密操作无法直接还原原始字符串。这个示例只是通过比对解密后的MD5值和原始字符串的MD5值来验证是否匹配。
     * @param encryptedString
     * @return
     */
    public static String decryptMD5(String encryptedString)  {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] encryptedBytes = new BigInteger(1, encryptedString.getBytes()).toByteArray();
            byte[] decryptedBytes = md.digest(encryptedBytes);

            StringBuilder sb = new StringBuilder();
            for (byte b : decryptedBytes) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            Log.i(TAG,"decryptMD5 exception:" + e);
            throw new RuntimeException(e);
        }
    }

    private static String setBase64(String str){
        // 对字符串进行Base64加密
        return  Base64.getEncoder().encodeToString(str.getBytes());
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
        Log.i(TAG,"test:" + setBase64("周星驰"));
//        Log.i("xwg","yanmumumumu with sha256 is:" + getSHA256("yanmumumumu"));
    }
}
