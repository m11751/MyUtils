package com.aidl.myutils.thread;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * 先进先出消息队列，三个线程同时发送消息，只保存时间最近发送的消息，其他丢弃
 * 输出：Received message from thread: Thread 1, message: Hello, World!，每次不一样
 */
public class MessageQueue {

    private BlockingQueue<Message> queue;

    private static class Message {
        private String message;
        private String senderThreadName;

        public Message(String message, String senderThreadName) {
            this.message = message;
            this.senderThreadName = senderThreadName;
        }

        public String getMessage() {
            return message;
        }

        public String getSenderThreadName() {
            return senderThreadName;
        }
    }

    public MessageQueue() {
        this.queue = new LinkedBlockingQueue<>(1); // 限制队列大小为1，以实现只保存最近的一个消息
    }

    public void sendMessage(String message) {
        try {
            String senderThreadName = Thread.currentThread().getName();
            Message newMessage = new Message(message, senderThreadName);
            this.queue.put(newMessage); // 将消息添加到队列中
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void receiveMessage() {
        try {
            Message message = this.queue.take(); // 获取队列中的消息，如果队列为空则会阻塞
            System.out.println("Received message from thread: " + message.getSenderThreadName() + ", message: " + message.getMessage());
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        MessageQueue messageQueue = new MessageQueue();

        Thread thread1 = new Thread(() -> {
            messageQueue.sendMessage("Hello, World!");
        }, "Thread 1");

        Thread thread2 = new Thread(() -> {
            messageQueue.sendMessage("Hello, World!");
        }, "Thread 2");

        Thread thread3 = new Thread(() -> {
            messageQueue.sendMessage("Hello, World!");
        }, "Thread 3");

        thread1.start();
        thread2.start();
        thread3.start();

        messageQueue.receiveMessage();
    }
}



