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

    /**
     * 大端顺序存储的内容转换为相应的数值，最多8bytes。
     * 
     * @param bys
     * @param off
     * @param len
     * @return 返回转换后的值，如果len > 8 , 则返回前8位的值。
     * @throws Exception
     */
    public static long bigEndianToLong(byte[] bys, int off, int len) {
        if (len > 8)
            len = 8;
        long uint32 = 0;
        for (int i = 0, end = len - 1, c = end; i <= end; i++, c--) {
            uint32 |= (0xff & bys[off + i]) << (8 * c);
        }
        return uint32;
    }
    /**
     * 小端顺序存储的内容转换为相应的数值，最多8bytes。
     * 
     * @param bys
     * @param off
     * @param len
     * @return 返回转换后的值，如果len > 8 , 则返回前8位的值。
     * @throws Exception
     */
    public static long litterEndianToLong(byte[] bys, int off, int len) {
        if (len > 8)
            len = 8;
        long uint32 = 0;
        for (int i = len - 1; i >= 0; i--) {
            uint32 |= (0xff & bys[off + i]) << (8 * i);
        }
        return uint32;
    }
}
