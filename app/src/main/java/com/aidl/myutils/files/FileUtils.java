package com.aidl.myutils.files;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * 文件工具类
 */
public class FileUtils {
    /**
     * 查找指定文件中的是否包含指定字符串方法1
     * @param context   上下文
     * @param fileName  文件名
     * @param target    字符串
     * @throws IOException  IO
     */
    public static void searchWithStr(Context context, String fileName, String target) throws IOException {
        AssetManager assetManager = context.getAssets();
        InputStream inputStream = assetManager.open(fileName);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        String result = null;
        while ((line = reader.readLine()) != null) {
            if (line.contains(target)) {
                System.out.println("has found:");
                System.out.println(fileName + ": " + line);
                result = line;
            }
        }
        System.out.println("search result:" + result);
        reader.close();
    }

    /**
     * 查找指定文件中的是否包含指定字符串方法2，searchWithStr优化后的方法
     * @param context   上下文
     *      * @param fileName  文件名
     *      * @param target    字符串
     *      * @throws IOException  IO
     */
    public static String search(Context context, String fileName, String target) throws IOException {
        AssetManager assetManager = context.getAssets();
        InputStream inputStream = assetManager.open(fileName);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        StringBuilder resultBuilder = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            if (line.contains(target)) {
                resultBuilder.append(line).append(System.lineSeparator());
            }
        }
        reader.close();
        String result = resultBuilder.toString().trim();
        System.out.println("Search result for " + target + " in " + fileName + ": " + result);
        return result;
    }

    /**
     * 查找指定文件中的是否包含指定字符串方法3，
     * @param context   上下文
     *      * @param fileName  文件名
     *      * @param target    字符串
     * @return  找到true，否则false
     *      * @throws IOException  IO
     */
    public static boolean search2(Context context, String fileName, String target) throws IOException {
        boolean rs = false;
        AssetManager assetManager = context.getAssets();
        InputStream inputStream = assetManager.open(fileName);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        StringBuilder resultBuilder = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            if (line.contains(target)) {
                resultBuilder.append(line).append(System.lineSeparator());
                rs = true;
            }
        }
        reader.close();
        String result = resultBuilder.toString().trim();
        System.out.println("Search result for " + target + " in " + fileName + ": " + result);
        return rs;
    }

    /**
     * search2优化后的代码:
     *使用：searchForStringInAssetFile(TtgActivity.this.getBaseContext(),"device_test.json", "abc");
     * @param context   context
     * @param fileName  文件名
     * @param target 搜索的字符串
     * @return  boolean 类型，找到返回true，否则false
     * @throws IOException  io异常
     */
    public static boolean searchForStringInAssetFile(Context context, String fileName, String target) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(context.getAssets().open(fileName)))) {
            boolean result = reader.lines().anyMatch(line -> line.contains(target));
            System.out.println("Search result for " + target + " in " + fileName + ": " + (result ? target : "not found"));
            return result;
        }
    }

}
