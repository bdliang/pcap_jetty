package pcap.test;

import pcap.decode.HttpDecode;
import pcap.utils.BasicUtils;

public class JavaTest {

    public static void main(String[] args) {
        test2();
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
}
