package com.aidl.myutils.thread;

import android.util.Log;

/**
 * 使用synchronization关键字同步:<java核心技术卷1>12版p593
 * 2023-04-15 11:03:14.988 30888-30941 System.out              com.aidl.myutils                     I  Thread[Thread-19,5,main]
 * 2023-04-15 11:03:14.988 30888-30941 System.out              com.aidl.myutils                     I      507.25 from 17 to 32 Total Balance:  100000.00
 * 2023-04-15 11:03:14.988 30888-30963 System.out              com.aidl.myutils                     I  Thread[Thread-41,5,main]
 * 2023-04-15 11:03:14.988 30888-30963 System.out              com.aidl.myutils                     I      940.36 from 39 to 85 Total Balance:  100000.00
 * 2023-04-15 11:03:14.989 30888-30937 System.out              com.aidl.myutils                     I  Thread[Thread-16,5,main]
 * 2023-04-15 11:03:14.989 30888-30937 System.out              com.aidl.myutils                     I      233.36 from 14 to 70 Total Balance:  100000.00
 *
 * 使用条件对象后金额正确:<java核心技术卷1>12版p589
 * 2023-04-15 10:26:02.880  6740-6780  System.out              com.aidl.myutils                     I  Thread[Thread-5,5,main]
 * 2023-04-15 10:26:02.880  6740-6780  System.out              com.aidl.myutils                     I      142.74 from 3 to 42 Total Balance:  100000.00
 * 2023-04-15 10:26:02.880  6740-6872  System.out              com.aidl.myutils                     I  Thread[Thread-85,5,main]
 * 2023-04-15 10:26:02.880  6740-6872  System.out              com.aidl.myutils                     I      750.24 from 83 to 86 Total Balance:  100000.00
 * 2023-04-15 10:26:02.880  6740-6860  System.out              com.aidl.myutils                     I  Thread[Thread-73,5,main]
 * 2023-04-15 10:26:02.881  6740-6860  System.out              com.aidl.myutils                     I      197.41 from 71 to 81 Total Balance:  100000.00
 *
 * 使用重入锁后金额正确:<java核心技术卷1>12版p585
 2023-04-15 10:00:12.601 21677-21834 System.out              com.aidl.myutils                     I  Thread[Thread-101,5,main]
 2023-04-15 10:00:12.601 21677-21834 System.out              com.aidl.myutils                     I      497.42 from 99 to 97 Total Balance:  100000.00
 2023-04-15 10:00:12.601 21677-21753 System.out              com.aidl.myutils                     I  Thread[Thread-21,5,main]
 2023-04-15 10:00:12.601 21677-21753 System.out              com.aidl.myutils                     I      380.31 from 19 to 48 Total Balance:  100000.00
 2023-04-15 10:00:12.601 21677-21740 System.out              com.aidl.myutils                     I  Thread[Thread-8,5,main]
 2023-04-15 10:00:12.601 21677-21740 System.out              com.aidl.myutils                     I      114.36 from 6 to 41 Total Balance:  100000.00
 *
 * 非同步线程的模拟取钱操作,竞态同步操作,<java核心技术卷1>12版p582
 * 输出的金额不对:
 * 2023-04-15 09:53:22.414 17410-17504 System.out              com.aidl.myutils                     I  Thread[Thread-50,5,main]
 * 2023-04-15 09:53:22.414 17410-17546 System.out              com.aidl.myutils                     I  Thread[Thread-92,5,main]
 * 2023-04-15 09:53:22.414 17410-17466 System.out              com.aidl.myutils                     I  Thread[Thread-12,5,main]
 * 2023-04-15 09:53:22.414 17410-17527 System.out              com.aidl.myutils                     I      591.36 from 10 to 7Thread[Thread-73,5,main]
 * 2023-04-15 09:53:22.414 17410-17535 System.out              com.aidl.myutils                     I  Thread[Thread-81,5,main]
 * 2023-04-15 09:53:22.414 17410-17535 System.out              com.aidl.myutils                     I      793.98 from 79 to 46 Total Balance:   94186.19
 * 2023-04-15 09:53:22.414 17410-17480 System.out              com.aidl.myutils                     I  Thread[Thread-26,5,main]
 * 2023-04-15 09:53:22.414 17410-17512 System.out              com.aidl.myutils                     I       33.80 from 24 to 41Thread[Thread-58,5,main]
 * 2023-04-15 09:53:22.415 17410-17512 System.out              com.aidl.myutils                     I      913.87 from 56 to 73 Total Balance:   94186.19
 */
public class UnsynchBankTest {
    public static final int NACCOUNTS = 10; //账户个数
    public static final double INITIAL_BALANCE = 1000;  //账户初始值
    public static final double MAX_AMOUNT = 1000;   //最大转账限制金额
    public static final int DELAY = 10; //休眠时间

    /**
     * 多线程转账操作测试
     * @param args  命令行参数
     */
    public static void main(String[] args) {
//        var bank = new Bank(NACCOUNTS,INITIAL_BALANCE);
//        var bank = new BankReentrantLock(NACCOUNTS,INITIAL_BALANCE);
//        var bank = new BankCondition(NACCOUNTS,INITIAL_BALANCE);
        var bank = new BankSynchronization(NACCOUNTS,INITIAL_BALANCE );  //新建账户
        for (int i = 0; i < NACCOUNTS; i++){
            int fromAccount = i;
            Runnable r = () ->{
                try{
                    while (true){   //随机转账
                        int toAccount = (int)(bank.size() * Math.random());
                        double amount = 2 * MAX_AMOUNT * Math.random();
                        bank.transfer(fromAccount,toAccount,amount);
                        Thread.sleep((int)(DELAY * Math.random()));
                    }
                }catch (InterruptedException e){
                    Log.i("xwg", "InterruptedException:" + e);
                }
            };
            var t = new Thread(r);
            t.start();
        }
    }
}
