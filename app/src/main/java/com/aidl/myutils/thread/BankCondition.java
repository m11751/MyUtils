package com.aidl.myutils.thread;

import java.util.Arrays;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * virtual bank bean,加入重入锁的保护,加入条件对象
 * 代表了一个虚拟银行，其中包含一个表示各账户余额的 accounts 数组。
 */
public class BankCondition {
    private final double[] accounts;
    private Lock bankLock = new ReentrantLock();
    private final Condition sufficientFunds;  //资金充足条件
    /**
     *银行类
     * @param n 账户数量
     * @param initialBalance    账户初始余额
     */
    public BankCondition(int n, double initialBalance) {
        accounts = new double[n];
        Arrays.fill(accounts,initialBalance);   //于给数组 accounts 中的所有元素赋初始值为 initialBalance。
        bankLock = new ReentrantLock();
        sufficientFunds = bankLock.newCondition();  //返回一个跟锁相关联的条件
    }

    /**
     * 转账
     * InterruptedException是Java中的一个Checked Exception，通常在多线程编程中使用，用于表示线程被中断或阻塞时抛出的异常。
     * 例如，当一个线程处于阻塞状态，而另一个线程中断了它时，阻塞线程就会抛出InterruptedException异常。
     * @param from  转出账户
     * @param to    转入账户
     * @param amount    余额
     */
    public void transfer(int from, int to, double amount) throws InterruptedException{
        bankLock.lock();
        try {
            while (accounts[from] < amount)
                sufficientFunds.await();    //将该线程放在这个条件的等待集中
            System.out.println(Thread.currentThread());
            accounts[from] -= amount;
            System.out.printf("%10.2f from %d to %d", amount, from, to);
            accounts[to] += amount;
            System.out.printf(" Total Balance: %10.2f%n" ,getTotalBalance());
            sufficientFunds.signalAll();    //解除改条件等待集中所有线程的阻塞状态
        } finally {
            bankLock.unlock();
        }
    }

    /**
     *
     * @return 计算银行所有账户的总余额。
     */
    private double getTotalBalance() {
        bankLock.lock();
        try {
            double sum = 0;
            for (double a : accounts)
                sum += a;
            return sum;
        } finally {
            bankLock.unlock();
        }
    }

    /**
     *
     * @return 返回银行的账户数量。
     */
    public int size(){
        return accounts.length;
    }
}
