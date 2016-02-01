package pcap.message;

import net.sf.json.JSONArray;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 从 ConnectionPairMap中 将map的values值复制过来
 * 
 * 等待数据收集的request
 * 
 * 
 * 
 * 
 * */

@Deprecated
public class TcpLinksForRequest {

    private static TcpLinksForRequest single;

    private static int ToBufferTime = 0;

    public static final int LOAD_TIMES_TO_CLEAN = 20;
    public static final int DELAY_TO_COLLECT = 2;
    public static final int TIME_INTERVAL = 2;
    public static final TimeUnit TIMEUNIT = TimeUnit.SECONDS;

    private List<TcpLink> list = null;

    private TcpLinksForRequest() {
        list = new ArrayList<TcpLink>();
    }

    public static TcpLinksForRequest getInstance() {
        if (null == single) {
            synchronized (TcpLinksForRequest.class) {
                if (null == single) {
                    single = new TcpLinksForRequest();
                }
            }
        }
        return single;
    }

    public List<TcpLink> getList() {
        return list;
    }

    public void printTcpLinks() {
        System.out.println("\nprint tcp links : xxx" + ToBufferTime);
        // for (TcpLink tcp : list) {
        // System.out.println(tcp.toString());
        // }
        System.out.println(jsonTcpLinks());
        System.out.println("\nprint tcp links : xxx" + ToBufferTime);
    }

    public String printTcpLinks1() {
        StringBuilder builder = new StringBuilder();
        System.out.println("\nprint tcp links : " + ToBufferTime);
        for (TcpLink tcp : list) {
            builder.append(tcp.toString() + "\n");
        }
        return builder.toString();
    }

    public String jsonTcpLinks() {

        JSONArray jsonArray = JSONArray.fromObject(list);

        return jsonArray.toString();
    }

    /**
     * 需要检查 是否把 ConnectionPairMap中的记录清除。
     * */
    public void clean() {
        list.clear();
    }

    public void collectInformation() {
        ConnectionPairMap map = ConnectionPairMap.getInstance();
        ++ToBufferTime;
        boolean isClean = false;
        if (0 == ToBufferTime % LOAD_TIMES_TO_CLEAN) {
            ToBufferTime = 0;
            isClean = true;
            System.out.println("ready to clean");
        }
        map.tranferValuesToBuffer(list, isClean);
        // printTcpLinks();
    }

}
