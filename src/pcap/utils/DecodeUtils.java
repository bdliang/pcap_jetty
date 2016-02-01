package pcap.utils;

public class DecodeUtils {

    public static int pin4bytes(byte b1, byte b2, byte b3, byte b4) {
        return (((b1 << 8) | b2) << 8 | b3) << 8 | b4;
    }

    public static int pin3bytes(byte b1, byte b2, byte b3) {
        return ((b1 << 8) | b2) << 8 | b3;
    }

    public static int pinIntfromString(String str, int end) {
        if (null == str || end > str.length() || end > 4)
            return -1;
        int re = 0, i;
        for (i = 0; i < end; ++i) {
            re = (re << 8) | ((int) str.charAt(i));
        }
        return re;
    }

    public static int pinIntFromBytes(byte[] buf, int end) {
        if (null == buf || end > buf.length || end > 4)
            return -1;
        int re = 0, i;
        for (i = 0; i < end; ++i) {
            re = (re << 8) | buf[i];
        }
        return re;
    }

}
