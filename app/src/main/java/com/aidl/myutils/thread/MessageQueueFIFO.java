package com.aidl.myutils.thread;

import java.util.LinkedList;
import java.util.Queue;

/**
 * 以下是一个简单的 Java 先进先出 (FIFO) 消息队列的例子：
 * out:
 * 2023-04-21 10:49:46.771 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 1
 * 2023-04-21 10:49:46.772 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 1
 * 2023-04-21 10:49:47.772 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 2
 * 2023-04-21 10:49:47.772 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 2
 * 2023-04-21 10:49:48.772 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 3
 * 2023-04-21 10:49:48.772 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 3
 * 2023-04-21 10:49:49.773 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 4
 * 2023-04-21 10:49:49.774 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 4
 * 2023-04-21 10:49:50.774 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 5
 * 2023-04-21 10:49:50.774 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 5
 * 2023-04-21 10:49:51.775 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 6
 * 2023-04-21 10:49:51.775 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 6
 * 2023-04-21 10:49:52.776 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 7
 * 2023-04-21 10:49:52.776 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 7
 * 2023-04-21 10:49:53.776 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 8
 * 2023-04-21 10:49:53.776 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 8
 * 2023-04-21 10:49:54.776 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 9
 * 2023-04-21 10:49:54.776 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 9
 * 2023-04-21 10:49:55.777 28236-28273 System.out              com.aidl.myutils                     I  Sent: Message 10
 * 2023-04-21 10:49:55.777 28236-28274 System.out              com.aidl.myutils                     I  Received: Message 10
 */
public class MessageQueueFIFO {
    private Queue<String> queue;

    public MessageQueueFIFO() {
        queue = new LinkedList<>();
    }

    public synchronized void sendMessage(String message) {
        queue.offer(message);
        notifyAll();
    }

    public synchronized String receiveMessage() throws InterruptedException {
        while (queue.isEmpty()) {
            wait();
        }
        return queue.poll();
    }

    public static void main(String[] args) {
        MessageQueueFIFO messageQueue = new MessageQueueFIFO();

        // Sender thread sends messages to the queue
        Thread senderThread = new Thread(() -> {
            for (int i = 1; i <= 10; i++) {
                String message = "Message " + i;
                messageQueue.sendMessage(message);
                System.out.println("Sent: " + message);
                try {
                    Thread.sleep(1000); // Wait for 1 second
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        // Receiver thread receives messages from the queue
        Thread receiverThread = new Thread(() -> {
            try {
                for (int i = 1; i <= 10; i++) {
                    String message = messageQueue.receiveMessage();
                    System.out.println("Received: " + message);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });

        senderThread.start();
        receiverThread.start();
    }
}

