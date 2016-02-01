package pcap.test;

import pcap.core.CaptureCore;
import pcap.task.PcapEveryDayTask;
import pcap.task.PcapCleanTask;
import pcap.task.TaskManager;

import java.util.concurrent.TimeUnit;

public class CaptureTest {

    public static void main(String[] args) {

        // PropertyUtils.defaultConfiguration();
        // PropertyUtils.printRunTimeAppLayer();
        // PropertyUtils.printMapAppToPorts();

        // CaptureCore.printDevices();
        // CaptureCore.DisableCapture();
        // TcpLinksForRequest.collectInformation();
        // CaptureCore.startSniff(0, 30, 20, true);
        // TcpLinksForRequest.shutDown();

        PcapCleanTask t4Request = new PcapCleanTask("buffer");
        PcapEveryDayTask tClean = new PcapEveryDayTask("clean-per-day", 0, 0, 0);
        TaskManager manager = new TaskManager();
        manager.addPeriodTaskWith(t4Request);
        manager.addPeriodTaskAt(tClean);
        manager.addOnceTask(new CaptureCore(), 0, TimeUnit.SECONDS);
        // CaptureCore.startSniff(0, 30, 20, true);

    }
}
