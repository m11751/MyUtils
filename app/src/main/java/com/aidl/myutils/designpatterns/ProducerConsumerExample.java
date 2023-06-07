package com.aidl.myutils.designpatterns;

/**
 *下面是一个简单的Java生产者消费者模型的例子
 * 该例子中，生产者不断地往队列中添加元素，当队列已满时，生产者会等待，直到消费者消费元素并唤醒生产者。
 * 消费者不断地从队列中取出元素，当队列为空时，消费者会等待，直到生产者生产元素并唤醒消费者。
 * 使用synchronized和wait()、notify()方法来实现线程之间的同步与通信。
 */
import java.util.LinkedList;
import java.util.Queue;

public class ProducerConsumerExample {

    public static void main(String[] args) {
        Queue<Integer> queue = new LinkedList<>();
        int maxSize = 5;
        Thread producer = new Thread(new Producer(queue, maxSize)); //生产者
        Thread consumer = new Thread(new Consumer(queue));  //消费者
        producer.start();
        consumer.start();
    }

    /**
     * 生产者类
     */
    static class Producer implements Runnable {

        private final Queue<Integer> queue;
        private final int maxSize;

        public Producer(Queue<Integer> queue, int maxSize) {
            this.queue = queue;
            this.maxSize = maxSize;
        }

        @Override
        public void run() {
            int i = 0;
            while (true) {
                synchronized (queue) {
                    while (queue.size() == maxSize) {
                        try {
                            System.out.println("Queue is full, waiting for consumer to consume");
                            queue.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    System.out.println("Producing value : " + i);
                    queue.add(i++);
                    queue.notifyAll();
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
    /**
     * 消费者类
     */
    static class Consumer implements Runnable {

        private final Queue<Integer> queue;

        public Consumer(Queue<Integer> queue) {
            this.queue = queue;
        }

        @Override
        public void run() {
            while (true) {
                synchronized (queue) {
                    while (queue.isEmpty()) {
                        try {
                            System.out.println("Queue is empty, waiting for producer to produce");
                            queue.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    int value = queue.remove();
                    System.out.println("Consuming value : " + value);
                    queue.notifyAll();
                }
            }
        }
    }
}
