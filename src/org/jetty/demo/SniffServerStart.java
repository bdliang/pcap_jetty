package org.jetty.demo;

import java.util.concurrent.TimeUnit;

import pcap.core.CaptureCore;
import pcap.core.SniffInit;
import pcap.task.TaskManager;

public class SniffServerStart {

    public static void startSniff() {
        SniffInit.init();
        TaskManager manager = new TaskManager();
        // PcapCleanTask cleanTask = new PcapCleanTask("clean", 60, 60,
        // TimeUnit.SECONDS);
        // PcapLogTask logTask = new PcapLogTask("log", 5, 5, TimeUnit.SECONDS);
        // manager.addPeriodTaskAt(cleanTask);
        // manager.addPeriodTaskAt(logTask);
        manager.addOnceTask(new CaptureCore(), 0, TimeUnit.SECONDS);
        // CaptureCore.startSniffAllTime(1);
    }

    public static void startServer() {
        JettyCustomServer server = new JettyCustomServer("./jetty/etc/jetty.xml", "/testContext");
        server.startServer();
    }

    public static void main(String[] args) {
        startSniff();
        // startServer();
    }
}