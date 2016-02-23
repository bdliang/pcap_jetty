package pcap.core;

import pcap.constant.BasicConstants;
import pcap.utils.BasicUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

public class PortMonitorMap {

    private static final String DefaultPortPath = "./jetty/etc/port.properties";
    // private static final String DefaultArguPath =
    // "./jetty/etc/basic.properties";

    private static PortMonitorMap single;

    /* 存放所有监测的名称 */
    private static List<String> RunTimeAppLayer = null;

    /* 存放所有监测的名称 和对应端口号 */
    private static Map<String, List<Integer>> AppToPortsMap = null;

    private PortMonitorMap() {
        RunTimeAppLayer = new ArrayList<String>(10);
        AppToPortsMap = new HashMap<String, List<Integer>>(10);
    }

    public static PortMonitorMap getInstance() {
        if (null == single) {
            synchronized (PortMonitorMap.class) {
                if (null == single) {
                    single = new PortMonitorMap();
                }
            }
        }
        return single;
    }

    /**
     * 通过 应用层协议名， 查询对应端口是否在监测端口中
     * 
     * 如果 src端口是监控端口， 返回 OK_FOUND_SRC;如果 dst端口是监控端口， 返回 OK_FOUND_DST
     * 
     * 注意: ！！这里假设 src, dst不会同时是监控端口
     * */
    private int hasPortForApp(String app, int srcPort, int dstPort) {
        if (!BasicUtils.isPortValid(srcPort) || !BasicUtils.isPortValid(dstPort) || BasicUtils.isStringBlank(app))
            return BasicConstants.WRONG_ARGUMENT;

        if (!AppToPortsMap.containsKey(app))
            return BasicConstants.APP_NOT_FOUND;

        List<Integer> ports = AppToPortsMap.get(app);
        if (ports.contains(srcPort))
            return BasicConstants.OK_FOUND_SRC;
        if (ports.contains(dstPort))
            return BasicConstants.OK_FOUND_DST;
        return BasicConstants.NOT_FOUND;
    }

    /**
     * 监测 源，目的两个端口，是否有一个是监控的端口。
     * 
     * 如果源端口是监测端口， 返回对应应用协议名的序号 ;如果目的端口是监测端口， 返回 （对应应用协议名的序号） | DST_PORT_ENCODE
     * 次高位值1， 其余位不变， 结果 >= DST_PORT_ENCODE。
     * 
     * 如果端口号不规范， WRONG_ARGUMENT
     * 
     * 没找到， NOT_FOUND
     * */
    public int hasPort(int srcPort, int dstPort) {
        if (!BasicUtils.isPortValid(srcPort) || !BasicUtils.isPortValid(dstPort))
            return BasicConstants.WRONG_ARGUMENT;

        int i = 0;
        for (String str : RunTimeAppLayer) {
            if (BasicConstants.OK_FOUND_SRC == hasPortForApp(str, srcPort, dstPort)) {
                return i;
            }

            if (BasicConstants.OK_FOUND_DST == hasPortForApp(str, srcPort, dstPort)) {
                return i | BasicConstants.DST_PORT_ENCODE;
            }
            ++i;
        }
        return BasicConstants.NOT_FOUND;
    }

    public String AppLayerName(int index) {
        if (index < 0 || index >= RunTimeAppLayer.size())
            return "";
        return RunTimeAppLayer.get(index);
    }

    public void addNewAppForSniff(String str, List<Integer> ports) {
        if (null == RunTimeAppLayer || null == AppToPortsMap)
            return;

        if (RunTimeAppLayer.contains(str)) {
            // 重复， 忽略
            return;
        }
        RunTimeAppLayer.add(str.toLowerCase());
        AppToPortsMap.put(str.toLowerCase(), ports);
    }

    public void addNewAppForSniff(String str, int port) {
        if (!BasicUtils.isPortValid(port))
            return;
        addNewAppForSniff(str, Arrays.asList(port));
    }

    public void printRunTimeAppLayer() {
        System.out.println("\n#### RunTimeAppLayer ####");
        if (null == RunTimeAppLayer) {
            return;
        }
        for (String str : RunTimeAppLayer) {
            System.out.println(str);
        }
        System.out.println("\n#########################\n");
    }

    public void printMapAppToPorts() {
        System.out.println("\n#### AppToPortsMap ####");
        if (null == AppToPortsMap) {
            return;
        }

        for (Entry<String, List<Integer>> entry : AppToPortsMap.entrySet()) {
            System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue());
        }
        System.out.println("\n#######################\n");
    }

    public void printAll() {
        printRunTimeAppLayer();
        printMapAppToPorts();
    }

    public List<Integer> getAppPort(String appName) {
        return AppToPortsMap.get(appName);
    }

    /** load */
    public void loadPortsMapFromFile() {
        loadPortsMapFromFile(DefaultPortPath);
    }

    public void loadPortsMapFromFile(String filePath) {
        Properties pps = new Properties();
        if (null == filePath)
            return;

        try {
            InputStream in = new FileInputStream(filePath);
            pps.load(in);
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        for (Entry<Object, Object> entry : pps.entrySet()) {
            String str = new String((String) entry.getKey());
            List<Integer> result = new ArrayList<Integer>();
            String strValue = (String) entry.getValue();
            String[] subValues = strValue.split(",");
            for (int i = 0; i < subValues.length; ++i) {
                int re = BasicUtils.isPort(subValues[i].trim());
                if (-1 == re)
                    continue;
                result.add(re);
            }
            RunTimeAppLayer.add(str.toLowerCase());
            AppToPortsMap.put(str.toLowerCase(), result);
        }
        // printAll();
    }
}
