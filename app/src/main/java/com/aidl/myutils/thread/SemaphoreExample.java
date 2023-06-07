package com.aidl.myutils.thread;

import java.util.concurrent.Semaphore;

/**Semaphore的例子
 *
 * Semaphore是Java中一个同步工具类，用于控制线程的并发访问数量。它实际上是一种计数信号量，用于保证在同一时刻最多只有指定数量的线程可以访问某个资源。
 *
 * Semaphore有两个重要的方法：acquire()和release()。acquire()方法用于获取Semaphore的许可证，
 * 如果Semaphore当前的许可证数量为0，则当前线程将被阻塞直到有许可证可用。如果Semaphore的许可证数量大于0
 * ，则当前线程将获取一个许可证并继续执行。而release()方法则用于释放Semaphore的许可证，将许可证的数量加1。
 *
 * Semaphore可以用于多种场景，如控制资源的并发访问、控制线程的数量等。比如，一个数据库连接池中有多个连接，
 * 但是最多只能有N个线程同时使用，这时就可以使用Semaphore来控制线程的并发数量，确保同时只有最多N个线程在使用连接。
 *
 * 另外，Semaphore还有一个可选的构造方法，可以指定它是否公平，即许可证的获取是否按照FIFO原则分配给等待的线程。
 * 如果公平性被启用，Semaphore将维护一个等待队列，按照请求许可证的顺序为等待的线程分配许可证。如果禁用公平性，则Semaphore将随机分配许可证，无法保证请求许可证的顺序。
 *
 * 运行结果:
 * 2023-04-18 10:50:22.565 18077-18102 System.out              com.aidl.myutils                     I  Thread 1 is running
 * 2023-04-18 10:50:22.565 18077-18104 System.out              com.aidl.myutils                     I  Thread 3 is running
 * 2023-04-18 10:50:22.565 18077-18105 System.out              com.aidl.myutils                     I  Thread 4 is running
 * 2023-04-18 10:50:23.565 18077-18102 System.out              com.aidl.myutils                     I  Thread 1 has finished
 * 2023-04-18 10:50:23.565 18077-18104 System.out              com.aidl.myutils                     I  Thread 3 has finished
 * 2023-04-18 10:50:23.565 18077-18105 System.out              com.aidl.myutils                     I  Thread 4 has finished
 * 2023-04-18 10:50:23.565 18077-18103 System.out              com.aidl.myutils                     I  Thread 2 is running
 * 2023-04-18 10:50:23.566 18077-18106 System.out              com.aidl.myutils                     I  Thread 5 is running
 * 2023-04-18 10:50:24.567 18077-18106 System.out              com.aidl.myutils                     I  Thread 5 has finished
 * 2023-04-18 10:50:24.567 18077-18103 System.out              com.aidl.myutils                     I  Thread 2 has finished
 */
public class SemaphoreExample {
    /**
     * Semaphore的初始许可证数量为3，意味着最多只有3个线程能够同时执行。然后，我们启动了5个线程，并将Semaphore传递给每个线程。
     *  * 在每个线程的run()方法中，首先调用semaphore的acquire()方法获取许可证，如果没有可用的许可证，则线程将被阻塞直到有可用的许可证。
     *  * 接着，线程模拟执行了一个耗时操作，最后调用semaphore的release()方法释放许可证。
     *  *
     *  * 由于Semaphore的初始许可证数量为3，因此前3个线程可以直接获得许可证并执行，而后面的2个线程需要等待某个线程释放许可证后才能获取许可证并执行。
     *  * 这样就保证了同时只有最多3个线程在执行，其他线程需要等待。
     * @param args
     */
    public static void main(String[] args) {
        Semaphore sem = new Semaphore(3); // 最多只允许3个线程同时执行

        for (int i = 1; i <= 5; i++) {
            Thread t = new MyThreadSemaphore(sem, i);
            t.start();
        }
    }
}

class MyThreadSemaphore extends Thread {
    Semaphore sem;
    int threadNum;

    public MyThreadSemaphore(Semaphore sem, int threadNum) {
        this.sem = sem;
        this.threadNum = threadNum;
    }

    @Override
    public void run() {
        try {
            sem.acquire();
            System.out.println("Thread " + threadNum + " is running");
            Thread.sleep(1000); // 模拟线程执行的耗时操作
            System.out.println("Thread " + threadNum + " has finished");
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            sem.release();
        }
    }
}

