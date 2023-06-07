package com.aidl.myutils.thread;

/**
 * 在 Java 中，volatile 是一个关键字，用于修饰变量。被 volatile 修饰的变量可以保证在多线程环境下的可见性，
 * 即当一个线程修改了该变量的值后，其他线程能够立即看到修改后的值，从而避免了数据不一致的问题。
 *
 * 具体来说，当一个变量被 volatile 修饰后，编译器会在生成的汇编代码中添加一些指令，保证该变量的读写操作都是从主内存中读写的，
 * 而不是从线程的本地内存中读写的。这样可以确保在多个线程中访问该变量时，能够保证它们看到的值都是最新的值，从而避免了出现脏读、幻读等问题。
 *
 * 以下是一个使用 volatile 关键字的例子：
 * 在下面的例子中，定义了一个名为 flag 的 volatile 变量，并在 loop 方法中不断地读取它的值。
 * 同时，我们启动了一个新线程来执行 loop 方法，并在主线程中等待 1 秒钟后，将 flag 的值设置为 true，以退出 loop 方法的循环。
 *
 * 由于 flag 是一个 volatile 变量，因此在主线程中修改它的值后，新线程能够立即看到修改后的值，
 * 从而退出了 loop 方法的循环。如果没有使用 volatile 关键字来修饰 flag 变量，那么可能会出现新线程一直循环下去的情况，因为它无法感知到主线程中对 flag 的修改。
 *
 * result:
 * 2023-04-15 12:25:40.382 26102-26130 System.out              com.aidl.myutils                     I  do something..
 * 2023-04-15 12:25:40.382 26102-26130 System.out              com.aidl.myutils                     I  do something..
 * 2023-04-15 12:25:40.383 26102-26130 System.out              com.aidl.myutils                     I  do something..
 * 2023-04-15 12:25:40.384 26102-26130 System.out              com.aidl.myutils                     I  do something..
 * 2023-04-15 12:25:40.673 26102-26130 System.out              com.aidl.myutils                     I  do something..
 * 2023-04-15 12:25:40.673 26102-26130 System.out              com.aidl.myutils                     I  loop exited
 */
public class VolatileExample {
    private volatile boolean flag = false;  //只能声明字段

    public void setFlag(boolean flag) {
        this.flag = flag;
    }

    public void loop() {
        while (!flag) {
            // do something
            System.out.println("do something..");
        }
        System.out.println("loop exited");
    }

    public static void main(String[] args) throws Exception {
        VolatileExample example = new VolatileExample();

        // 启动一个线程来执行 loop 方法
        new Thread(() -> example.loop()).start();

        // 等待 1 秒钟后，将 flag 设置为 true，让 loop 方法退出循环
        Thread.sleep(1000);
        example.setFlag(true);
    }
}

