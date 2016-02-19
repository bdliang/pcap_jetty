package pcap.utils;

import pcap.decode.MysqlLengthEncodedInteger;

import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;

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
        long result = 0;
        for (int i = len - 1; i >= 0; i--) {
            result |= (0xff & bys[off + i]) << (8 * i);
        }
        return result;
    }

    /**
     * 尚未不完整
     * 
     * 通过characterSetCode 返回响应的字符集对象，如果出错则返回"UTF-8"对应的字符集.
     * 
     * 如果考虑mysql, 其实应该是 "ISO-8859-1"对应的字符集(latin1), 不过无所谓，反正目前相当于测试
     * */
    public static Charset charSet(int characterSetCode) {

        // 省略将对应characterSetCode转换为对应字符串
        // 需要补充

        String enc = "UTF-8";
        Charset charset = null;
        if (enc == null)
            return Charset.forName("UTF-8");

        try {
            charset = Charset.forName(enc);
        } catch (IllegalCharsetNameException e) {
            return Charset.forName("UTF-8");
        } catch (UnsupportedCharsetException e) {
            return Charset.forName("UTF-8");
        }
        return charset;
    }

    /**
     * mysql length-coeded integer的解码
     * */
    public static MysqlLengthEncodedInteger mysqlLengthCodedIntDecode(byte[] data, int offset) {
        if (null == data || data.length < offset + 1)
            return new MysqlLengthEncodedInteger(0L, 0, true);
        int first = BasicUtils.u(data[offset]);
        switch (first) {
            case 0xfc :
                return new MysqlLengthEncodedInteger(litterEndianToLong(data, offset + 1, 2), 2, false);
            case 0xfd :
                return new MysqlLengthEncodedInteger(litterEndianToLong(data, offset + 1, 3), 3, false);
            case 0xfe :
                return new MysqlLengthEncodedInteger(litterEndianToLong(data, offset + 1, 8), 8, false);
        }
        if (first >= 0xfb)
            return new MysqlLengthEncodedInteger(0L, 0, true);;
        return new MysqlLengthEncodedInteger(first, 1, false);
    }
}
