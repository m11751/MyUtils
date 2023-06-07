package com.aidl.myutils.list;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * list相关方法
 */
public class ListUtils {
    /**
     * 4种遍历方式及消耗时间
     * 2023-03-30 19:12:39.366 18547-18547 System.out              com.aidl.myutils                     I  for循环执行时间：3毫秒
     * 2023-03-30 19:12:39.369 18547-18547 System.out              com.aidl.myutils                     I  foreach循环执行时间：3毫秒
     * 2023-03-30 19:12:39.371 18547-18547 System.out              com.aidl.myutils                     I  迭代器执行时间：2毫秒
     * 2023-03-30 19:12:39.377 18547-18547 System.out              com.aidl.myutils                     I  Stream API执行时间：6毫秒
     * @param args
     */
    public static void main(String[] args) {
        // 初始化List
        List<Integer> myList = new ArrayList<>();
        for (int i = 0; i < 65536; i++) {
            myList.add(i);
        }

        // 1.测试for循环的执行时间
        long startTime1 = System.currentTimeMillis();
        for (int i = 0; i < myList.size(); i++) {
            int item = myList.get(i);
        }
        long endTime1 = System.currentTimeMillis();
        System.out.println("for循环执行时间：" + (endTime1 - startTime1) + "毫秒");

        // 2.测试foreach循环的执行时间
        long startTime2 = System.currentTimeMillis();
        for (int item : myList) {
        }
        long endTime2 = System.currentTimeMillis();
        System.out.println("foreach循环执行时间：" + (endTime2 - startTime2) + "毫秒");

        // 3.测试迭代器的执行时间
        long startTime3 = System.currentTimeMillis();
        Iterator<Integer> iterator = myList.iterator();
        while (iterator.hasNext()) {
            int item = iterator.next();
        }
        long endTime3 = System.currentTimeMillis();
        System.out.println("迭代器执行时间：" + (endTime3 - startTime3) + "毫秒");

        // 4.测试Stream API的执行时间
        long startTime4 = System.currentTimeMillis();
        myList.stream().forEach(item -> {   //需要注意的是，Java编译器在处理这种情况时会发出警告信息，提示我们可以将stream().forEach()方法简化为forEach()方法
        });
        long endTime4 = System.currentTimeMillis();
        System.out.println("Stream API执行时间：" + (endTime4 - startTime4) + "毫秒");
    }

    /**
     * 测试list的增删改查
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  增加:
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  apple
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  banana
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  orange
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  -------------------------------------------------------
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  查找:第一个:apple,最后一个:orange
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  -------------------------------------------------------
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  将第二个元素改为"pear":
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  apple
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  orange
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  pear
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  -------------------------------------------------------
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  删除后的结果:
     * 2023-03-30 19:13:34.758 19248-19248 System.out              com.aidl.myutils                     I  orange
     * 2023-03-30 19:13:34.759 19248-19248 System.out              com.aidl.myutils                     I  pear
     * 2023-03-30 19:13:34.759 19248-19248 System.out              com.aidl.myutils                     I  -------------------------------------------------------
     * @param args
     */
    public static void main1(String[] args) {
//        增加
        List<String> myList = new ArrayList<>();
        myList.add("apple");
        myList.add("banana");
        myList.add("orange");
        System.out.println("增加:");
//        lambda遍历方法
        myList.stream()
                .sorted()
                .forEach(System.out::println);
        System.out.println("-------------------------------------------------------");
//查找
        String firstItem = myList.get(0); // 获取第一个元素
        String lastItem = myList.get(myList.size() - 1); // 获取最后一个元素
        System.out.println("查找:" + "第一个:" + firstItem + ",最后一个:" + lastItem);
        System.out.println("-------------------------------------------------------");
//修改
        myList.set(1, "pear"); // 将第二个元素改为"pear"
        System.out.println("将第二个元素改为\"pear\":");
        myList.stream()
                .sorted()
                .forEach(System.out::println);
        System.out.println("-------------------------------------------------------");
//删除
        myList.remove(0); // 删除第一个元素
        myList.remove("banana"); // 删除元素"banana"
        System.out.println("删除后的结果:");
        myList.stream()
                .sorted()
                .forEach(System.out::println);
        System.out.println("-------------------------------------------------------");
    }
}
