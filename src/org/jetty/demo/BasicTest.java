package org.jetty.demo;

import pcap.utils.BasicUtils;
import pcap.utils.DecodeUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class BasicTest {

    public static void main(String[] args) {
        test7();
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

    public static void test_16To10() {
        long x = 0;
        x = 0xfa;
        for (x = 0xfa; x <= 0xff; ++x)
            System.out.println(Long.toHexString(x) + " " + x);

    }

    /**
     * 小段顺序测试
     */
    public static void test4() {

        byte[] bys = {-1, 00, 00, 00};
        for (int i = 0; i < bys.length; ++i) {
            System.out.println((int) bys[i] + "  " + (0xff & bys[i]));
        }
        long re = 0;
        try {
            re = DecodeUtils.litterEndianToLong(bys, 0, 9);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println(re);
    }

    private static int u(byte b) {
        return (b >= 0) ? b : b + 256;
        // return 0xff & b;
    }

    private static int u1(byte b) {
        // return (b >= 0) ? b : b + 256;
        return 0xff & b;
    }

    /**
     * 测试u1()正确性
     * */
    public static void test5() {
        int cnt = 0;
        byte i = 0;
        for (i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; ++i) {
            if (u(i) != u1(i))
                ++cnt;
        }
        i = Byte.MAX_VALUE;
        if (u(i) != u1(i))
            ++cnt;
        System.out.println(cnt);
    }

    public static void test6() {
        int x = 0;
        x = 2048;

        System.out.println(Integer.toHexString(~x));
    }

    public static void test7() {
        Set<String> charsetNames = Charset.availableCharsets().keySet();
        System.out.println("---The Number of jdk charset is " + charsetNames.size() + "---");

        Iterator<String> it = charsetNames.iterator();

        while (it.hasNext()) {
            String charsetName = it.next();
            System.out.println(charsetName);
        }
    }

    public static void test8() {
        String xml = "abc";
        StringBuffer sb = new StringBuffer();
        sb.append(xml);
        String xmString = "";
        String xmlUTF8 = "";
        try {
            xmString = new String(sb.toString().getBytes("UTF-8"));
            xmlUTF8 = URLEncoder.encode(xmString, "UTF-8");
            System.out.println("utf-8 编码：" + xmlUTF8);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Charset cs = Charset.forName("UTF-8");
        System.out.println(cs.toString());

    }
}
