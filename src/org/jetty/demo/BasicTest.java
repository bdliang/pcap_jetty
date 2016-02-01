package org.jetty.demo;

import pcap.utils.BasicUtils;

import java.util.HashMap;
import java.util.Map;

public class BasicTest {

    public static void main(String[] args) {
        test3();
    }
    public static void test1() {
        System.out.println(Long.toHexString(BasicUtils.LONG_HALF_ONE_HALF_ZERO));
        System.out.println(Long.toHexString(BasicUtils.LONG_HALF_ZERO_HALF_ONE));
    }

    public static void test2() {
        int t1 = 0x12345678;
        int t2 = 0x87654321;
        long test = BasicUtils.ping2Int(t2, t1);
        System.out.println(Integer.toHexString(t1));
        System.out.println(Integer.toHexString(t2));
        System.out.println(Long.toHexString(test));
        int a1 = BasicUtils.getHigh4BytesFromLong(test);
        int a2 = BasicUtils.getLow4BytesFromLong(test);
        System.out.println(Integer.toHexString(a1));
        System.out.println(Integer.toHexString(a2));
    }

    public static void test3() {

        Map<String, Integer> map = new HashMap<String, Integer>();
        map.put("a", 2);

        System.out.println(map.toString());

        if (map.containsKey("b")) {
            System.out.println("yes");
        }

        String s = "b";
        Integer p = map.get(s);
        if (null == p) {
            System.out.println("not found");
        } else {
            int tmp = p;
            System.out.println(s + " = " + tmp);
        }

    }
}
