package com.aidl.myutils.encryption;


import java.util.Random;

public class RandomNumberAndLetter {
    public static void main(String[] args) {
        String number = getRandomNumber(5); // 生成 5 位随机数字
        char letter = getRandomLetter(); // 生成随机字母
        String result = number + letter; // 将数字和字母组合成一个字符串
        System.out.println("随机字符串: " + result);
    }

    public static String getRandomNumber(int length) {
        StringBuilder number = new StringBuilder();
        Random r = new Random();
        for(int i=0; i<length; i++) {
            number.append(r.nextInt(10));
        }
        return number.toString();
    }

    public static char getRandomLetter() {
        Random r = new Random();
        char[] c = new char[26];
        for(int i=0; i<26; i++) {
//            c[i] = (char)(97 + i);    //Letter
                        c[i] = (char)(65 + i);    //Letter
        }

        int randomIndex = r.nextInt(26);
        return c[randomIndex];
    }
}