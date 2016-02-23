package pcap.task;

import pcap.constant.BasicConstants;
import pcap.table.TcpTable;

import java.util.Calendar;

public class PcapEveryDayTask extends AbstractTask {

    private int hourOfDay;
    private int minuteOfHour;
    private int secondOfMinite;

    public PcapEveryDayTask(int hourOfDay, int minuteOfHour, int secondOfMinite) {
        this("Every-Day-Task", hourOfDay, minuteOfHour, secondOfMinite);
    }

    public PcapEveryDayTask(String name, int hourOfDay, int minuteOfHour, int secondOfMinite) {
        super(name);
        this.hourOfDay = hourOfDay;
        this.minuteOfHour = minuteOfHour;
        this.secondOfMinite = secondOfMinite;

        setInitialDelay(getEarliestDate() / 1000);
        setPeriod(BasicConstants.SECONDS_OF_A_DAY);
    }

    /**
     * 计算从当前时间currentDate开始，与每天定时时间的差 milliseconds
     * 
     * @return
     */
    public long getEarliestDate() {
        // 计算当前时间的WEEK_OF_YEAR,DAY_OF_WEEK, HOUR_OF_DAY, MINUTE,SECOND等各个字段值

        Calendar currentDate = Calendar.getInstance();
        Calendar taskDate = Calendar.getInstance();

        taskDate.set(Calendar.HOUR_OF_DAY, hourOfDay);
        taskDate.set(Calendar.MINUTE, minuteOfHour);
        taskDate.set(Calendar.SECOND, secondOfMinite);

        long cha = taskDate.getTime().getTime() - currentDate.getTime().getTime();
        if (cha < 0)
            cha += BasicConstants.SECONDS_OF_A_DAY * 1000;
        return cha;
    }

    @Override
    public void run() {
        System.err.println("每天任务");
        TcpTable.getInstance().clean();
    }
}
