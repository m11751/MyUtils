package com.aidl.myutils.thread;

/**
 * 线程的用法
 *
 * 2023-04-08 14:33:14.122  8773-8773  System.out              com.aidl.myutils                     I  sleep 5000ms
 * 2023-04-08 14:33:14.123  8773-8861  System.out              com.aidl.myutils                     I  Count: 0
 * 2023-04-08 14:33:14.123  8773-8861  System.out              com.aidl.myutils                     I  sleep 1000ms
 * 2023-04-08 14:33:15.123  8773-8861  System.out              com.aidl.myutils                     I  Count: 1
 * 2023-04-08 14:33:15.123  8773-8861  System.out              com.aidl.myutils                     I  sleep 1000ms
 * 2023-04-08 14:33:16.123  8773-8861  System.out              com.aidl.myutils                     I  Count: 2
 * 2023-04-08 14:33:16.124  8773-8861  System.out              com.aidl.myutils                     I  sleep 1000ms
 * 2023-04-08 14:33:17.125  8773-8861  System.out              com.aidl.myutils                     I  Count: 3
 * 2023-04-08 14:33:17.125  8773-8861  System.out              com.aidl.myutils                     I  sleep 1000ms
 * 2023-04-08 14:33:18.242  8773-8861  System.out              com.aidl.myutils                     I  Count: 4
 * 2023-04-08 14:33:18.243  8773-8861  System.out              com.aidl.myutils                     I  sleep 1000ms
 * 2023-04-08 14:33:19.123  8773-8773  System.out              com.aidl.myutils                     I  join()...
 * 2023-04-08 14:33:19.124  8773-8861  System.out              com.aidl.myutils                     I  Interrupted
 * 2023-04-08 14:33:19.124  8773-8773  System.out              com.aidl.myutils                     I  Main thread finished
 */
public class MyThread extends Thread {
    private int count;

    public void run() {
        while (!isInterrupted() && count < 10) {
            try {
                System.out.println("Count: " + count);
                System.out.println("sleep 1000ms");
                Thread.sleep(1000);
                count++;
            } catch (InterruptedException e) {
                System.out.println("Interrupted");
                return;
            }
        }
    }//end run

    public static void main(String[] args) {
        MyThread thread = new MyThread();
        thread.start();

        try {
            System.out.println("sleep 5000ms");
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        thread.interrupt(); //中断线程

        try {
            System.out.println("join()...");
            thread.join();  //等待目标线程执行完再继续执行
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("Main thread finished");
    }
}

