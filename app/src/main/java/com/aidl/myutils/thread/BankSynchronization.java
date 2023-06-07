package com.aidl.myutils.thread;

import java.util.Arrays;

/**
 * virtual bank bean,使用Synchronization
 * 在 Java 中，Synchronization 通常通过 synchronized 关键字实现。
 * 当一个方法或一个代码块被 synchronized 关键字修饰时，它就成为了一个临界区（Critical Section），同一时刻只能有一个线程访问它，
 * 其他线程必须等待当前线程执行完毕后才能访问。这样可以保证共享资源的正确性和一致性，避免数据竞争和并发访问带来的问题
 * 代表了一个虚拟银行，其中包含一个表示各账户余额的 accounts 数组。
 */
public class BankSynchronization {
    private final double[] accounts;

    /**
     *
     * @param n 账户数量
     * @param initialBalance    账户初始余额
     */
    public BankSynchronization(int n, double initialBalance) {
        accounts = new double[n];
        Arrays.fill(accounts,initialBalance);
    }

    /**
     * 转账,使用synchronized 关键字同步
     * @param from  转出账户
     * @param to    转入账户
     * @param amount    余额
     */
    public synchronized void transfer(int from, int to, double amount) throws InterruptedException{
        while (accounts[from] < amount)
            wait();
        System.out.println(Thread.currentThread());
        accounts[from] -= amount;
        System.out.printf("%10.2f from %d to %d", amount, from, to);
        accounts[to] += amount;
        System.out.printf(" Total Balance: %10.2f%n" ,getTotalBalance());
        notifyAll(); //解除对象调用wait方法的线程阻塞状态,只能在同步方法/同步块中调用,若线程不是对象锁拥有者,会抛出IllegalMonitorStateException
        /**
         * IllegalMonitorStateException 是 Java 中的一个异常类，表示某个线程试图在没有获得对象锁的情况下调用 wait()、notify() 或 notifyAll() 方法。
         *
         * 在 Java 中，wait()、notify() 和 notifyAll() 都是 Object 类的实例方法，用于实现线程之间的协作和同步。
         * 这些方法必须在 synchronized 块或方法内部调用，因为只有在持有对象锁的情况下才能调用这些方法。
         *
         * 如果某个线程在没有获得对象锁的情况下调用了 wait()、notify() 或 notifyAll() 方法，就会抛出 IllegalMonitorStateException 异常。
         * 这通常是由于程序员的错误导致的，如在没有获取对象锁的情况下调用 wait() 方法，或者在错误的对象上调用 notify() 方法。
         *
         * 为了避免出现 IllegalMonitorStateException 异常，程序员应该在调用 wait()、notify() 或 notifyAll() 方法之前，
         * 先获取对象锁，通常使用 synchronized 关键字来实现锁定。同时，程序员还应该确保在正确的对象上调用这些方法，避免出现对象混淆导致的异常。
         */
    }

    /**
     *使用synchronized 同步
     * @return 计算银行所有账户的总余额。
     */
    public synchronized double getTotalBalance() {
        double sum = 0;
        for (double a : accounts)
            sum += a;
        return sum;
    }

    /**
     *
     * @return 返回银行的账户数量。
     */
    public int size(){
        return accounts.length;
    }
}
