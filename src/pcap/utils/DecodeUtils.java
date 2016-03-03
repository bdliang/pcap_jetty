package pcap.utils;

import org.bson.BSONObject;
import org.bson.BasicBSONDecoder;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;

import pcap.constant.MongDBCommand;
import pcap.decode.MysqlLengthEncodedInteger;

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
     * 小端顺序存储的内容转换为相应的数值，最多8bytes。
     * 
     * @param bys
     * @param off
     * @param len
     * @return 返回转换后的值，如果len > 8 , 则返回前8位的值。
     * @throws Exception
     */
    public static int litterEndianToInt(byte[] bys, int off, int len) {
        if (len > 4)
            len = 4;
        int result = 0;
        for (int i = len - 1; i >= 0; i--) {
            result |= (0xff & bys[off + i]) << (8 * i);
        }
        return result;
    }

    /**
     * 尚未不完整
     * 
     * 通过characterSetCode 返回响应的字符集对象，如果出错则返回默认对应的字符集.
     * 
     * 如果考虑mysql, 默认字符集是 "ISO-8859-1"对应的字符集(latin1)。
     */
    public static Charset charSet(int characterSetCode) {

        // 省略将对应characterSetCode转换为对应字符串
        // 需要补充
        String enc = null;
        if (0x08 == characterSetCode) {
            enc = "ISO-8859-1";
        } else if (0x21 == characterSetCode) {
            enc = "UTF-8";
        }

        Charset charset = null;
        if (enc == null)
            return Charset.forName("ISO-8859-1");

        try {
            charset = Charset.forName(enc);
        } catch (IllegalCharsetNameException e) {
            return Charset.forName("ISO-8859-1");
        } catch (UnsupportedCharsetException e) {
            return Charset.forName("ISO-8859-1");
        }
        return charset;
    }

    /**
     * mysql length-coeded integer的解码
     * 
     * 将来可能会用到
     */
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

    /**
     * 将字节码转换成Bson对象 ，用于MongoDB的解析。
     * 
     * @param data
     *            待解析的数据
     * @param off
     *            起始位置
     * @param len
     *            长度
     */
    public static BSONObject bytesToBSONObject(byte[] data, int off, int len) {
        if (null == data || data.length < 1 || off < 0 || len < 0 || off + len > data.length)
            return null;
        BSONObject bson = null;
        ByteArrayInputStream in = new ByteArrayInputStream(data, off, len);
        BasicBSONDecoder tmp = new BasicBSONDecoder();
        try {
            bson = tmp.readObject(in);
            return bson;
        } catch (Exception e) {
            // e.printStackTrace();
            return null;
        }
    }

    /**
     * 将字节码按照c风格来转换成String对象。
     * 
     * @param data
     *            待解析的数据
     * @param off
     *            起始位置
     * @param len
     *            界限
     */
    public static String bytesToString(byte[] data, int off, int len) {
        if (null == data || data.length < 1 || off < 0 || len < 0 || off + len > data.length)
            return null;
        int i, end;
        for (i = off; i < len; ++i) {
            if (0x00 == data[i])
                break;
        }
        end = i + 1;
        if (end > len)
            return "";
        try {
            return new String(data, off, i, "UTF-8");
        } catch (Exception e) {
            // e.printStackTrace();
            return "";
        }
    }

    /***/
    public static boolean isMongoDBCommand(String key, String value) {
        boolean result = false;
        for (String command : MongDBCommand.commands) {
            if (command.equalsIgnoreCase(key)) {
                result = true;
                break;
            }
        }
        if (result && !BasicUtils.isStringBlank(value)) {
            return true;
        }
        return false;
    }

}
