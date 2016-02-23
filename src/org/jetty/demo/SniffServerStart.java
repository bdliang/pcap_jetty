package org.jetty.demo;

import pcap.core.CaptureCore;
import pcap.core.ProgramInit;
import pcap.task.PcapCleanTask;
import pcap.task.PcapLogTask;
import pcap.task.TaskManager;

import java.util.concurrent.TimeUnit;

public class SniffServerStart {

    public static void startSniff() {
        ProgramInit.init();
        TaskManager manager = new TaskManager();
        PcapCleanTask cleanTask = new PcapCleanTask("clean", 60, 60, TimeUnit.SECONDS);
        PcapLogTask logTask = new PcapLogTask("log", 5, 5, TimeUnit.SECONDS);
        manager.addPeriodTaskAt(cleanTask);
        manager.addPeriodTaskAt(logTask);
        manager.addOnceTask(new CaptureCore(), 0, TimeUnit.SECONDS);
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