package pcap.test;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;
import pcap.decode.HttpDecode;
import pcap.record.TcpRecord;
import pcap.table.TableAction;
import pcap.utils.BasicUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;

public class JavaTest {

    public static void main(String[] args) {
        test5();
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
        String url = HttpDecode.urlDivide(rawUrl);
        System.out.println(url);
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
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static void test5() {
        String rawUrl = "/abcdefg";
        String url = HttpDecode.urlDivide(rawUrl);
        System.out.println(url);
    }

}
