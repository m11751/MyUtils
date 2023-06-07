package com.aidl.myutils.thread;

import java.util.concurrent.Semaphore;

/**
 * 线程工具类,使用SemaphoreDemo限制运行的线程个数
 *
 * 在Java中，Semaphore对象可以在多个线程之间共享，并且可以保证多个线程之间对许可证的修改是可见的。
 * 但是，Semaphore对象本身不是线程安全的，如果在多个线程中同时修改Semaphore对象的状态，可能会导致竞态条件和线程安全问题。
 * 因此，在使用Semaphore对象时，需要遵守线程安全的规则，例如使用synchronized关键字来保证同步访问。
 *
 * 该示例创建了一个Semaphore对象，该对象的许可证数量为2，然后启动了5个线程来尝试获取许可证。
 * 由于每个线程都需要在开始执行前获得一个许可证，因此只有前两个线程能够获得许可证并执行任务，而其余的线程必须等待某个线程释放许可证后(等待1s)才能获得许可证并执行任务。
 *
 * 2023-04-08 11:17:05.766 26314-26366 System.out              com.aidl.myutils                     I  线程1获得了许可证
 * 2023-04-08 11:17:05.767 26314-26369 System.out              com.aidl.myutils                     I  线程4获得了许可证
 * 2023-04-08 11:17:06.767 26314-26369 System.out              com.aidl.myutils                     I  线程4释放了许可证
 * 2023-04-08 11:17:06.767 26314-26366 System.out              com.aidl.myutils                     I  线程1释放了许可证
 * 2023-04-08 11:17:06.767 26314-26368 System.out              com.aidl.myutils                     I  线程3获得了许可证
 * 2023-04-08 11:17:06.767 26314-26370 System.out              com.aidl.myutils                     I  线程5获得了许可证
 * 2023-04-08 11:17:07.767 26314-26368 System.out              com.aidl.myutils                     I  线程3释放了许可证
 * 2023-04-08 11:17:07.767 26314-26370 System.out              com.aidl.myutils                     I  线程5释放了许可证
 * 2023-04-08 11:17:07.768 26314-26367 System.out              com.aidl.myutils                     I  线程2获得了许可证
 * 2023-04-08 11:17:08.768 26314-26367 System.out              com.aidl.myutils                     I  线程2释放了许可证
 */
public class SemaphoreDemo {
    public static void main(String[] args) {
        Semaphore semaphore = new Semaphore(2);

        for (int i = 1; i <= 5; i++) {
            Thread t = new MyThread(i, semaphore);
            t.start();
        }
    }

    static class MyThread extends Thread {
        private final int num;
        private final Semaphore semaphore;

        public MyThread(int num, Semaphore semaphore) {
            this.num = num;
            this.semaphore = semaphore;
        }

        public void run() {
            try {
                semaphore.acquire();
                System.out.println("线程" + num + "获得了许可证");
                Thread.sleep(1000);
                System.out.println("线程" + num + "释放了许可证");
                semaphore.release();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}