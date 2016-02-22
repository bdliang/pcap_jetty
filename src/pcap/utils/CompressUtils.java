package pcap.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class CompressUtils {

    /**
     * zlib压缩
     * 
     * @param data
     *            待压缩数据
     * @return byte[] 压缩后的数据
     */
    public static byte[] zlibCompress(byte[] data) {
        return zlibCompress(data, 0, data.length);
    }

    /**
     * zlib压缩
     * 
     * @param data
     *            待压缩数据
     * @param offset
     *            压缩数据起始位置
     * @param length
     *            压缩数据长度
     * @return byte[] 压缩后的数据
     */
    public static byte[] zlibCompress(byte[] data, int offset, int length) {
        byte[] output = new byte[0];

        Deflater compresser = new Deflater();

        compresser.reset();
        try {
            compresser.setInput(data, offset, length);
        } catch (Exception e) {
            return null;
        }
        compresser.finish();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);
        try {
            byte[] buf = new byte[1024];
            while (!compresser.finished()) {
                int i = compresser.deflate(buf);
                bos.write(buf, 0, i);
            }
            output = bos.toByteArray();
        } catch (Exception e) {
            output = data;
            e.printStackTrace();
        } finally {
            try {
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        compresser.end();
        return output;
    }

    /**
     * zlib压缩
     * 
     * @param data
     *            待压缩数据
     * @param os
     *            输出流
     */
    public static void zlibCompress(byte[] data, OutputStream os) {
        zlibCompress(data, 0, data.length);
    }

    /**
     * zlib压缩
     * 
     * @param data
     *            待压缩数据
     * @param offset
     *            压缩数据起始位置
     * @param length
     *            压缩数据长度
     * @param os
     *            输出流
     */
    public static void zlibCompress(byte[] data, int offset, int length, OutputStream os) {
        DeflaterOutputStream dos = new DeflaterOutputStream(os);

        try {
            dos.write(data, offset, length);

            dos.finish();

            dos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * zlib解压缩
     * 
     * @param data
     *            压缩的数据
     * @return byte[] 解压缩后的数据
     */
    public static byte[] zlibDecompress(byte[] data) {
        return zlibDecompress(data, 0, data.length);
    }

    /**
     * zlib解压缩
     * 
     * @param data
     *            待压缩数据
     * @param offset
     *            压缩数据起始位置
     * @param length
     *            压缩数据长度
     * @return byte[] 解压缩后的数据
     */
    public static byte[] zlibDecompress(byte[] data, int offset, int length) {
        byte[] output = null;

        Inflater decompresser = new Inflater();
        decompresser.reset();
        try {
            decompresser.setInput(data, offset, length);
        } catch (Exception e) {
            return null;
        }

        ByteArrayOutputStream o = new ByteArrayOutputStream(data.length);
        try {
            byte[] buf = new byte[1024];
            while (!decompresser.finished()) {
                int i = decompresser.inflate(buf);
                o.write(buf, 0, i);
            }
            output = o.toByteArray();
        } catch (Exception e) {
            output = data;
            e.printStackTrace();
        } finally {
            try {
                o.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        decompresser.end();
        return output;
    }

    /**
     * zlib解压缩
     * 
     * @param is
     *            输入流
     * @return byte[] 解压缩后的数据
     */
    public static byte[] zlibDecompress(InputStream is) {
        if (null == is)
            return null;
        InflaterInputStream iis = new InflaterInputStream(is);
        ByteArrayOutputStream o = new ByteArrayOutputStream(1024);
        try {
            int i = 1024;
            byte[] buf = new byte[i];

            while ((i = iis.read(buf, 0, i)) > 0) {
                o.write(buf, 0, i);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return o.toByteArray();
    }

}
