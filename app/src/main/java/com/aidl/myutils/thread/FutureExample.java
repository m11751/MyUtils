package com.aidl.myutils.thread;

/**
 * 在Java中，Future是一个接口，用于表示异步计算的结果。它提供了一种获取并行执行的计算结果的方式。计算结果可能不会立即可用，但可以在稍后的时间获取到。
 *
 * 下面是一个简单的Java代码示例，演示了如何使用Future：
 * 2023-05-31 10:43:20.448 18251-18277 System.out              com.aidl.myutils                     I  executorService.submit...
 * 2023-05-31 10:43:21.787 18251-18267 System                  com.aidl.myutils                     W  A resource failed to call close.
 * 2023-05-31 10:43:22.448 18251-18251 System.out              com.aidl.myutils                     I  计算结果: 42
 */
import java.util.concurrent.*;

public class FutureExample {
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        // 创建一个Future对象，表示返回Integer类型结果的计算
        Future<Integer> future = executorService.submit(new Callable<Integer>() {
            @Override
            public Integer call() throws Exception {
                // 模拟耗时的计算
                System.out.println("executorService.submit...");
                Thread.sleep(2000);
                return 42;
            }
        });

        // 在计算进行中执行其他任务

        // 从Future中获取结果（阻塞操作）
        Integer result = future.get();

        System.out.println("计算结果: " + result);

        // 关闭ExecutorService
        executorService.shutdown();
    }
}

