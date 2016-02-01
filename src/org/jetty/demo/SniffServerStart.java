package org.jetty.demo;

import pcap.core.CaptureCore;
import pcap.task.PcapCleanTask;
import pcap.task.TaskManager;

import java.util.concurrent.TimeUnit;

//���࣬���
public class SniffServerStart {
    public static void main(String[] args) {

        // PcapForRequestTask t4Request = new PcapForRequestTask("buffer");
        // PcapEveryDayTask tClean = new PcapEveryDayTask("clean-per-day", 0, 0,
        // 0);
        PcapCleanTask cleanTask = new PcapCleanTask("clean", 60, 60, TimeUnit.SECONDS);
        TaskManager manager = new TaskManager();
        // manager.addPeriodTaskWith(t4Request);
        manager.addPeriodTaskAt(cleanTask);
        manager.addOnceTask(new CaptureCore(), 0, TimeUnit.SECONDS);

        JettyCustomServer server = new JettyCustomServer("./jetty/etc/jetty.xml", "/testContext");
        server.startServer();

    }
}