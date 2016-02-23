package pcap.utils;

import java.util.List;

public class BasicUtils {

    public static final int ETHERNET_HEADER_LEN = 6;
    public static final int IP_HEADER_LEN = 4;

    public static final String MAC_ADDR_SEPERATOR = "-";
    public static final String IP_ADDR_SEPERATOR = ".";

    public static final int NUM_EACH_CAPTURE = 10;
    public static final int DEFAULT_TIMEOUT = 500; // in millis

    /**
     * 将byte型按位转换成相应无符号整数值
     * */
    public static int u(byte b) {
        // return (b >= 0) ? b : b + 256;
        return 0xff & b;
    }

    public static String IpAddrToString(byte[] addr) {
        if (IP_HEADER_LEN != addr.length)
            return null;
        else {
            StringBuilder tmp = new StringBuilder();
            int i = 0;
            for (i = 0; i < IP_HEADER_LEN - 1; ++i) {
                tmp.append(u(addr[i]) + IP_ADDR_SEPERATOR);
            }
            tmp.append(u(addr[i]));
            return tmp.toString();
        }
    }

    public static void printIpAddr(byte[] addr) {
        System.out.println(IpAddrToString(addr));
    }

    public static String macAddrToString(byte[] addr) {
        if (ETHERNET_HEADER_LEN != addr.length)
            return null;
        else {
            StringBuilder tmp = new StringBuilder();
            int i = 0;
            for (i = 0; i < ETHERNET_HEADER_LEN - 1; ++i) {
                tmp.append(Integer.toHexString(u(addr[i])) + MAC_ADDR_SEPERATOR);
            }
            tmp.append(Integer.toHexString(u(addr[i])));
            return tmp.toString();
        }
    }

    public static void printMacAddr(byte[] addr) {
        System.out.println(macAddrToString(addr));
    }

    public static boolean isArrayValid(Object[] array) {
        if (null == array || 0 == array.length)
            return false;
        return true;
    }

    public static boolean isListValid(List<?> list) {
        if (null == list || 0 == list.size())
            return false;
        return true;
    }

    public static void printList(List<Integer> l) {
        if (null == l)
            return;
        for (Integer i : l) {
            System.out.println(i);
        }
        System.out.println();
    }

    public static void clearList(List<String> l) {
        if (null == l)
            return;
        l.clear();
    }

    public static boolean isStringBlank(String str) {
        return (null == str || 0 == str.length()) ? true : false;
    }

    public static long LONG_HALF_ZERO_HALF_ONE = Integer.MAX_VALUE * 2L + 1;
    public static long LONG_HALF_ONE_HALF_ZERO = LONG_HALF_ZERO_HALF_ONE << 32;
    public static int INT_HALF_ZERO_HALF_ONE = 0xffff;

    // 将2个int 拼成一个 long 按位
    public static long ping2Int(int int1, int int2) {
        long x1 = ((long) int1) << 32;
        long x2 = ((long) int2) & LONG_HALF_ZERO_HALF_ONE;
        x2 = ((long) int2) << 32 >>> 32;

        return x1 | x2;
    }

    public static int getHigh4BytesFromLong(long ipPair) {
        return (int) (ipPair >>> 32);
    }
    public static int getLow4BytesFromLong(long ipPair) {
        return (int) ipPair;
    }

    public static int getHigh2BytesFromLong(int portPair) {
        return portPair >>> 16;
    }
    public static int getLow2BytesFromLong(int portPair) {
        return portPair & INT_HALF_ZERO_HALF_ONE;
    }

    // 将2个port 拼成一个 int 按位
    public static int ping2port(int int1, int int2) {
        int x1 = int1 << 16;
        int x2 = int2 & INT_HALF_ZERO_HALF_ONE;
        return x1 | x2;
    }

    // ip 是网络序（大端序，高位在起始地址。 ）
    public static String intToIp(int ip) {
        byte[] x = new byte[4];
        x[0] = (byte) (ip >>> 24);
        x[1] = (byte) (ip >>> 16);
        x[2] = (byte) (ip >>> 8);
        x[3] = (byte) (ip);
        StringBuilder str = new StringBuilder();
        int i;
        for (i = 0; i < 3; ++i) {
            str.append(u(x[i]) + BasicUtils.IP_ADDR_SEPERATOR);
        }
        str.append(u(x[i]));
        return str.toString();
    }

    public static int ipStringToInt(String ipStr) {
        String[] fields = ipStr.split("\\.");
        if (4 != fields.length)
            return 0;
        int result = 0, tmp, i;
        for (i = 0; i < 4; ++i) {
            result = result << 8;
            tmp = Integer.parseInt(fields[i]);
            if (tmp < 0 || tmp > 255) {
                return 0;
            }
            result += tmp;
        }
        return result;
    }

    public static void printTcpPayLoad(byte[] payload) {
        if (null == payload)
            return;
        for (int i = 0; i < payload.length; ++i) {
            // if (0 == i % 48)
            // System.out.println();
            System.out.print((char) payload[i]);
        }
        System.out.println();
    }

    public static boolean isPortValid(int port) {
        return (port >= 0 && port <= 65535) ? true : false;
    }
}
