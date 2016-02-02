//PropertyUtils

package pcap.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

public class PropertyUtils {

    public static final int WRONG_ARGUMENT = -3;
    public static final int APP_NOT_FOUND = -2;
    public static final int NOT_FOUND = -1;
    public static final int OK_FOUND = 0;
    public static final int OK_FOUND_SRC = 1;
    public static final int OK_FOUND_DST = 2;

    public static final int DST_PORT_ENCODE = 0x40000000;
    public static final int DST_PORT_DECODE = 0x3fffffff;

    public static final String DefaultPortPath = "./jetty/etc/port.properties";

    public static final String DefaultArguPath = "./jetty/etc/basic.properties";

    public static List<Integer> getPortsForKey(String key) {
        return getPortsForKeyFromFile(DefaultPortPath, key);
    }

    public static List<Integer> getPortsForKeyFromFile(String filePath, String key) {
        Properties pps = new Properties();
        if (null == filePath)
            return null;

        try {
            InputStream in = new FileInputStream(filePath);
            pps.load(in);
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        List<Integer> result = new ArrayList<Integer>();
        String strValue = pps.getProperty(key);
        String[] subValues = strValue.split(",");
        for (int i = 0; i < subValues.length; ++i) {
            int re = isPort(subValues[i].trim());
            if (-1 == re)
                continue;
            result.add(re);
        }
        return (0 == result.size()) ? null : result;
    }

    public static void loadBasicArgument() {
        loadBasicArgument(DefaultPortPath);
    }

    public static void loadBasicArgument(String filePath) {
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
        // String cleantime = pps.getProperty("cleantime");
    }

    public static void loadPortsMapFromFile() {
        loadPortsMapFromFile(DefaultPortPath);
    }

    public static void loadPortsMapFromFile(String filePath) {
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
                int re = isPort(subValues[i].trim());
                if (-1 == re)
                    continue;
                result.add(re);
            }
            RunTimeAppLayer.add(str.toLowerCase());
            AppToPorts.put(str.toLowerCase(), result);
        }
        // printMapAppToPorts();
    }

    // public static String[] AppLayer = {"http", "mysql", "pgsql", "mongodb",
    // "redis"};

    /* 存放所有监测的名称 */
    private static List<String> RunTimeAppLayer = null;

    /* 存放所有监测的名称 和对应端口号 */
    private static Map<String, List<Integer>> AppToPorts = null;

    public static String AppLayerName(int index) {
        if (index < 0 || index > RunTimeAppLayer.size())
            return "";
        return RunTimeAppLayer.get(index);
    }

    public static void initBasicArgument() {
        initAppLayer();
        initMapAppToPorts();
    }

    public static void defaultConfiguration() {
        initBasicArgument();
        loadPortsMapFromFile();
    }

    public static void initAppLayer() {
        if (null == RunTimeAppLayer) {
            RunTimeAppLayer = new ArrayList<String>(10);
        } else
            RunTimeAppLayer.clear();
    }

    public static void initMapAppToPorts() {
        if (null == AppToPorts) {
            AppToPorts = new HashMap<String, List<Integer>>(10);
        } else
            AppToPorts.clear();
    }

    public static void addNewAppForSniff(String str, List<Integer> ports) {
        if (null == RunTimeAppLayer || null == AppToPorts) {
            initBasicArgument();
        }

        if (RunTimeAppLayer.contains(str)) {
            // 重复， 忽略
            return;
        }
        RunTimeAppLayer.add(str.toLowerCase());
        AppToPorts.put(str.toLowerCase(), ports);
    }

    public static void printRunTimeAppLayer() {
        if (null == RunTimeAppLayer) {
            return;
        }
        for (String str : RunTimeAppLayer) {
            System.out.println(str);
        }
        System.out.println();
    }

    public static void printMapAppToPorts() {
        if (null == AppToPorts) {
            return;
        }

        for (Entry<String, List<Integer>> entry : AppToPorts.entrySet()) {
            System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue());
        }
        System.out.println();
    }

    public static List<Integer> getAppPort(String appName) {
        return AppToPorts.get(appName);
    }

    public static int isPort(String str) {
        try {
            int num = Integer.valueOf(str);
            return (num >= 0 && num <= 65535) ? num : -1;
        } catch (Exception e) {
            return -1;
        }
    }

    public static boolean isPortValid(int port) {
        return (port >= 0 && port <= 65535) ? true : false;
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
    public static int hasPort(int srcPort, int dstPort) {
        if (!isPortValid(srcPort) || !isPortValid(dstPort))
            return WRONG_ARGUMENT;

        int i = 0;
        for (String str : RunTimeAppLayer) {
            if (OK_FOUND_SRC == hasPortForApp(str, srcPort, dstPort)) {
                return i;
            }

            if (OK_FOUND_DST == hasPortForApp(str, srcPort, dstPort)) {
                return i | DST_PORT_ENCODE;
            }
            ++i;
        }
        return NOT_FOUND;
    }

    public static int EnCode(int i) {
        if (i > PropertyUtils.DST_PORT_ENCODE)
            return i | DST_PORT_ENCODE;
        return i;
    }

    public static int DeCode(int i) {
        if (i >= PropertyUtils.DST_PORT_ENCODE)
            return i & DST_PORT_DECODE;
        return i;
    }

    /**
     * 通过 应用层协议名， 查询对应端口是否在监测端口中
     * 
     * 如果 src端口是监控端口， 返回 OK_FOUND_SRC;如果 dst端口是监控端口， 返回 OK_FOUND_DST
     * 
     * 注意: ！！这里假设 src, dst不会同时是监控端口
     * */
    public static int hasPortForApp(String app, int srcPort, int dstPort) {
        if (!isPortValid(srcPort) || !isPortValid(dstPort) || BasicUtils.isStringBlank(app))
            return WRONG_ARGUMENT;

        if (!AppToPorts.containsKey(app))
            return APP_NOT_FOUND;

        List<Integer> ports = AppToPorts.get(app);
        if (ports.contains(srcPort))
            return OK_FOUND_SRC;
        if (ports.contains(dstPort))
            return OK_FOUND_DST;
        return NOT_FOUND;

    }

}
