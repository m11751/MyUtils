package com.aidl.myutils.thread;

import java.util.Arrays;

/**
 * virtual bank bean
 * 代表了一个虚拟银行，其中包含一个表示各账户余额的 accounts 数组。
 */
public class Bank {
    private final double[] accounts;

    /**
     *
     * @param n 账户数量
     * @param initialBalance    账户初始余额
     */
    public Bank(int n, double initialBalance) {
        accounts = new double[n];
        Arrays.fill(accounts,initialBalance);
    }

    /**
     * 转账
     * @param from  转出账户
     * @param to    转入账户
     * @param amount    余额
     */
    public void transfer(int from, int to, double amount){
        if (accounts[from] < amount) return;
        System.out.println(Thread.currentThread());
        accounts[from] -= amount;
        System.out.printf("%10.2f from %d to %d", amount, from, to);
        accounts[to] += amount;
        System.out.printf(" Total Balance: %10.2f%n" ,getTotalBalance());
    }

    /**
     *
     * @return 计算银行所有账户的总余额。
     */
    private double getTotalBalance() {
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
