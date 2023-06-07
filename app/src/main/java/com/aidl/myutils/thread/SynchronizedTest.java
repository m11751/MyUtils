package com.aidl.myutils.thread;

/**
 * 下面是一个使用 synchronized 实现多线程同步的例子，该例子演示了使用两个线程分别对共享变量 count 进行自增操作，保证了多线程操作 count 的线程安全性。
 * 即使用synchronized 关键字保证count 总数不变
 */
public class SynchronizedTest {
    private static int count = 0;

    public static void main(String[] args) {
        Thread t1 = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 100000; i++) {
                    increment();
                }
            }
        });

        Thread t2 = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 100000; i++) {
                    increment();
                }
            }
        });

        t1.start();
        t2.start();

        try {
            t1.join();  //t1执行完成才执行t2
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("Count: " + count);
    }

    private synchronized static void increment() {
        count++;
    }
}

