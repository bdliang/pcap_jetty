package pcap.test;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;
import pcap.record.TcpRecord;
import pcap.table.TableAction;
import pcap.utils.BasicUtils;
import pcap.utils.DecodeUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;

public class JavaTest {

    public static void main(String[] args) {
        test7();
    }

    public static void test1() {
        int i, j;
        final int FANWEI = 65536;
        int cnt = 0;
        for (i = 0; i < FANWEI; ++i) {
            for (j = 0; j < FANWEI; ++j) {
                int xx = BasicUtils.ping2port(i, j);
                int x1 = BasicUtils.getHigh2BytesFromLong(xx);
                int x2 = BasicUtils.getLow2BytesFromLong(xx);
                if (i != x1 || j != x2)
                    ++cnt;
            }
        }

        System.out.println("cnt = " + cnt);
    }

    public static void test2() {
        String rawUrl = "/abcdefg?asdasda";
        // String url = HttpDecode.urlDivide(rawUrl);
        // System.out.println(url);
    }

    // json属性控制
    public static void test3() {
        TcpRecord t = new TcpRecord(1, 2, 3, 4, -1);
        JSONObject jobj = JSONObject.fromObject(t);
        System.out.println(jobj);

        JsonConfig config = new JsonConfig();
        config.setExcludes(new String[]{// 只要设置这个数组，指定过滤哪些字段。
        "info", "type", "timeStamp"});
        jobj = JSONObject.fromObject(t, config);
        System.out.println(jobj);
    }

    // 输出文件设置
    public static void test4() {
        File file = new File(TableAction.filePath);
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fileWritter = new FileWriter(file.getName(), true);
            BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
            bufferWritter.write(new Date(System.currentTimeMillis()).toString() + "\n");
            bufferWritter.write("hello\n");
            bufferWritter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void test5() {
        String rawUrl = "/abcdefg";
        // String url = HttpDecode.urlDivide(rawUrl);
        // System.out.println(url);
    }

    public static final int BYTETOVALUE = 0x00ff;
    public static void test6() {
        // 将byte型(当做无符号)转换成int型，
        // byte x = (byte) 0xff;
        // int tmp = x;
        // System.out.println("tmp = " + tmp);
        //
        // tmp = x & BYTETOVALUE;
        // System.out.println("tmp = " + tmp);

        // 将4个byte拼成一个int
        byte[] b = new byte[4];

        b[0] = 0x01;
        b[1] = 0x01;
        b[2] = 0x01;
        b[3] = 0x01;
        int re = DecodeUtils.pin4bytes(b[0], b[1], b[2], b[3]);
        System.out.println(Integer.toHexString(re));
        int re1 = 0;
        for (int i = 0; i < b.length; ++i) {
            re1 *= 256;
            re1 += b[i] & BYTETOVALUE;
        }
        System.out.println(Integer.toHexString(re1));
        if (re == re1)
            System.out.println("yes");
        else
            System.out.println("no");
    }

    /**
     * byte[] 转化为 String
     * */
    public static void test7() {

        String str = "352e312e392d716c7068612d646562756700";
        System.out.println(str.length());

    }
}
