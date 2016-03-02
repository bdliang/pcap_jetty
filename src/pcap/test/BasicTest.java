package pcap.test;

import org.bson.BSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import pcap.constant.MongDBCommand;
import pcap.constant.MongDBOpCode;
import pcap.record.MysqlServerRecord.MysqlItems;
import pcap.utils.BasicUtils;
import pcap.utils.CompressUtils;
import pcap.utils.DecodeUtils;

public class BasicTest {

    public static void main(String[] args) {
        test18();
    }

    public static void test1() {
        // System.out.println(Long.toHexString(BasicUtils.LONG_HALF_ONE_HALF_ZERO));
        // System.out.println(Long.toHexString(BasicUtils.LONG_HALF_ZERO_HALF_ONE));
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
     */
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
        System.out.println("---The Number of jdk charset is "
                + charsetNames.size() + "---");

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

    public static void test9() {
        // mysql 压缩,解压缩测试
        // 参考
        // http://dev.mysql.com/doc/internals/en/example-one-mysql-packet.html
        String sql = "select \"012345678901234567890123456789012345\"";
        byte[] data = null;
        byte[] compressData = null;
        data = sql.getBytes();

        byte[] data1 = new byte[5 + data.length];
        data1[0] = 0x2e;
        data1[1] = 0x00;
        data1[2] = 0x00;
        data1[3] = 0x00;
        data1[4] = 0x03;
        for (int i = 0; i < data.length; ++i) {
            data1[5 + i] = data[i];
        }

        data = data1;
        printBytes(data);
        compressData = CompressUtils.zlibCompress(data);
        printBytes(compressData);
        data = CompressUtils.zlibDecompress(compressData);
        printBytes(data);
        String sql1 = new String(data, 5, data.length - 5);
        System.out.println(sql);
        System.out.println(sql1);
        System.out.println(sql.equals(sql1));
    }

    public static void test10() {
        // String str =
        // "78 9c d3 63 60 60 60 2e 4e cd 49 4d 2e 51 50 32 30 34 32 36 31 35 33
        // b7 b0 c4 cd 52 02 00 0c d1 0a 6c ";
        // byte[] data = charNumToBytes(str);
        // printBytes(data);
        // data = CompressUtils.decompress(data, 0, data.length, 45);
        // printBytes(data);
        // String sql1 = new String(data);
        // System.out.println(sql1);
    }

    public static byte[] charNumToBytes(String str) {
        if (null == str)
            return null;
        int[] tmp = new int[1024];
        int cnt = 0;
        int i = 0;
        int curByte = 0;
        int curNum = 0;
        for (i = 0; i < str.length(); ++i) {
            char c = str.charAt(i);
            if (c >= '0' && c <= '9') {
                curByte = c - '0';
                curNum = curNum * 16 + curByte;
            } else if (c >= 'a' && c <= 'f') {
                curByte = 10 + c - 'a';
                curNum = curNum * 16 + curByte;
            } else {
                tmp[cnt++] = curNum;
            }
        }

        byte[] result = new byte[cnt];
        for (i = 0; i < cnt; ++i) {
            result[i] = (byte) tmp[i];
        }
        return result;
    }

    public static void printBytes(byte[] data) {
        printBytes(data, 0, data.length);
    }

    public static void printBytes(byte[] data, int offset, int length) {
        if (null == data) {
            System.out.println("null pointer in BasicTest.printBytes()");
            return;
        }
        if (offset < 0 || length < 0 || offset > data.length - length) {
            System.out.println("wrong arguments in BasicTest.printBytes()");
            return;
        }
        System.out.println(
                "length : 0x " + Integer.toHexString(length) + "  = " + length);
        int cnt = 0;
        final int eightBytes = 8;
        final int hexBytes = 16;
        for (byte b : data) {
            System.out.print(Integer.toHexString(b & 0xff) + " ");
            ++cnt;
            if (0 == cnt % eightBytes)
                System.out.print(" ");
            if (0 == cnt % hexBytes)
                System.out.println();
        }

        System.out.println("\n###############");
    }

    public static void test11() {
        for (MysqlItems item : MysqlItems.values()) {
            System.out.println(item.name());
        }
    }

    public static void test12() {
        String str = "1a";
        try {
            int tmp = Integer.parseInt(str);
            System.out.println(tmp);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("hh");
    }

    public static void test13() {
        byte[] payload = new byte[20];
        int i = 0;
        for (i = 0; i < payload.length; ++i)
            payload[i] = (byte) 0xff;
        for (i = 0; i < payload.length; ++i) {
            System.out.print((payload[i]) + " ");
        }
        System.out.println();

        int tmp = (int) DecodeUtils.litterEndianToLong(payload, 0, 4);
        System.out.println(tmp);
    }

    public static void test14() {
        int tmp, i = 0;
        tmp = MongDBOpCode.OP_DELETE;
        System.out.println(MongDBOpCode.isOpCodeValid(tmp) + " " + ++i);
    }

    public static void test15() {
        String str = "awesome";
        for (char c : str.toCharArray()) {
            System.out.print(Integer.toHexString(c) + " ");
        }
        System.out.println();
    }

    /**
     * bson 测试
     */
    public static void test16() {
        String str = "16 00 00 00 02 68 65 6c 6c 6f 00 06 00 00 00 77 6f 72 6c 64 00 00 ";
        byte[] data = charNumToBytes(str);
        BSONObject tmp = null;
        tmp = DecodeUtils.bytesToBson(data, 0, data.length);
        System.out.println(tmp.toString());
        String str1 = "31 00 00 00 04 42 53 4f 4e 00 26 00 00 00 02 30 00 08 00 00 00 61 77 65 73 6f 6d 65 00 01 31 00 33 33 33 33 33 33 14 40 10 32 00 c2 07 00 00 00 00 ";
        data = charNumToBytes(str1);
        tmp = DecodeUtils.bytesToBson(data, 0, data.length);
        System.out.println(tmp.toString());

        for (String strTmp : tmp.keySet()) {
            System.out.println(strTmp + " : " + tmp.get(strTmp));
        }
    }

    public static void test17() {
        // for (String str : MongDBCommand.commands) {
        // System.out.println(str);
        // }
        // System.out.println("####################\n");
        // Arrays.sort(MongDBCommand.commands);
        // for (String str : MongDBCommand.commands) {
        // System.out.println(str);
        // }

        String str = MongDBCommand.getMongDBCommand(0);
        System.out.println(str);
        Arrays.sort(MongDBCommand.commands);
        str = MongDBCommand.getMongDBCommand(0);
        System.out.println(str);
    }

    public static void test18() {
        int tmp = 2;
        switch (tmp) {
            case 1 :
                System.out.println("1");
                System.out.println("1");
                break;
            case 2 :
                System.out.println("2");
                System.out.println("2");
                break;
            case 3 :
                System.out.println("3");
                System.out.println("3");
                break;
            case 4 :
                System.out.println("4");
                System.out.println("4");
                break;
            case 5 :
                System.out.println("5");
                System.out.println("5");
                break;
            default :
                System.out.println("default");
        }

    }
}
