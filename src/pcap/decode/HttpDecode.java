package pcap.decode;

import org.jnetpcap.protocol.tcpip.Tcp;

import pcap.constant.TcpStatus;
import pcap.record.TcpRecord;
import pcap.record.UrlRecord;
import pcap.table.UrlTable;
import pcap.utils.DecodeUtils;

public class HttpDecode {

    /**
     * 通过tcp的payload来拆http包
     * 
     * http包 分为 (1)请求行/状态行(2)头部(3)空行(4)包体
     * 
     * 
     * 由于目前只是需要对(1)进行拆解
     * 
     * payload 是byte[]类型。 所以需要通过前几个字节来判断此包是不是一个完整的http包，或者是被拆分后的第一个包。
     * 
     * 也就是是不是符合http包的格式。
     * 
     * */

    /**
     * 所有http的方法(第一个除外，那是用来判断是不是response包)
     * 
     * 
     * http 请求包必定以这里的某个方法为开始
     * 
     * 每个方法前3个字节连起来都不相同，采用拼接成int型来判断。
     * */

    public static final String[] HTTP_METHOD = {"HTTP", "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT"};

    static {
        generateMETHODCODE();
    }

    /**
     * 用来判定http包是否是response
     * */
    public static int[] HTTP_METHOD_CODE;

    public static void generateMETHODCODE() {
        HTTP_METHOD_CODE = new int[HTTP_METHOD.length];
        for (int i = 0; i < HTTP_METHOD.length; ++i) {
            HTTP_METHOD_CODE[i] = DecodeUtils.pinIntfromString(HTTP_METHOD[i], 3);
            // System.out.println(Integer.toHexString(HTTP_METHOD_CODE[i]));
        }
    }

    /** The Constant HEADER_DELIMITER. */
    private final static char[] HEADER_DELIMITER = {'\r', '\n', '\r', '\n'};

    private final static int NOT_HTTP = -1;

    public static int isBytesHTTPHeader(byte[] raw) {
        if (null == raw || 4 >= raw.length)
            return NOT_HTTP;
        int tmp = DecodeUtils.pin3bytes(raw[0], raw[1], raw[2]);
        for (int i = 0; i < HTTP_METHOD_CODE.length; ++i) {
            if (tmp == HTTP_METHOD_CODE[i])
                return i;
        }
        return NOT_HTTP;
    }

    /**
     * 返回http包中 (1)请求行/状态行(2)头部(3)空行的部分。
     * */
    public static String getHttpHeader(byte[] raw) {
        int httpType = isBytesHTTPHeader(raw);
        if (NOT_HTTP == httpType) {
            return null;
        }

        StringBuilder buf = new StringBuilder();
        int match = 0;
        for (int i = 0; i < raw.length; i++) {

            char c = (char) raw[i];
            char d = HEADER_DELIMITER[match];

            if (Character.isDefined(c) == false) {
                break;
            }
            buf.append(c);
            if (d == c) {
                match++;
                if (match == HEADER_DELIMITER.length) {
                    break;
                }
            } else {
                match = 0;
            }
        }
        return buf.toString();
    }

    public static void decodeFirstLine(String firstLine, TcpRecord record, long timeStamp) {
        String[] c = firstLine.split(" ");
        if (c.length < 3) {
            return; // Can't parse it
        }

        if (c[0].startsWith("HTTP")) {
            // response
            // c[0] --- version
            // c[1] --- code
            // c[2] --- codeMsg
            record.setStatus(TcpStatus.HTTP_RESPONSE);
            UrlRecord urlRecord = UrlTable.getInstance().getUrlRecord(record.typeIp(), record.typePort(), record.getInfo());
            if (null == urlRecord)
                return;
            urlRecord.addItem(c[1]);
            long start = record.getTimeStamp();
            if (-1 == start)
                return;
            urlRecord.addTimeRecord(timeStamp - start, start);

            // System.out.println("RESPONSE  " +
            // UrlTable.getInstance().getNum());
            // System.out.println(c[0]);
            // System.out.println(c[1]);
            // System.out.println(c[2] + "\n");
        } else {
            // request
            // c[0] --- method
            // c[1] --- url
            // c[2] --- version
            record.setStatus(TcpStatus.HTTP_REQUEST);
            record.setTimeStamp(timeStamp);
            String url = urlDivide(c[1]);
            record.setInfo(url);
            UrlRecord urlRecord = UrlTable.getInstance().getUrlRecord(record.typeIp(), record.typePort(), url);
            urlRecord.addItem(c[0]);

            // System.out.println("REQUEST  " +
            // UrlTable.getInstance().getNum());
            // // System.out.println(c[0]);
            // System.out.println(url);
            // System.out.println(c[2] + "\n");
        }
    }

    public static String urlDivide(String rawUrl) {
        if (null == rawUrl)
            return null;
        int index = rawUrl.indexOf('?');
        if (-1 == index)
            return rawUrl;
        return rawUrl.substring(0, index);
    }

    public static void decode(Tcp tcp, TcpRecord record, long timeStamp) {

        try {
            byte[] payload = tcp.getPayload();
            if (null == payload || null == record)
                return;

            // System.out.println("#### " + tcp.getPayloadLength() + " --- " +
            // payload.length);
            /* 判断是否是含有http包头的包 */
            String httpHeader = getHttpHeader(payload);
            if (httpHeader == null) {
                return;
            }
            // System.out.println("@@@@");
            // System.out.println(httpHeader);

            String[] lines = httpHeader.split("\r\n|\n");

            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (line.length() == 0) {
                    continue; // Skip 0 length/blank lines
                }

                /*
                 * First check if lines need to be combined if first character
                 * is a space or a tab. This indicates line continuation and all
                 * leading white space is replaced with a single space.
                 */
                char firstChar = line.charAt(0);
                if (firstChar == ' ' || firstChar == '\t') {
                    line = line.trim();
                    if (buf.length() != 0) {
                        buf.append(' ');
                    }

                    buf.append(line);
                    continue;
                } else {
                    /*
                     * Check if we have any buffered string in the buffer from
                     * the recombining process. If yes, we make take the string
                     * out of the buffer and process it, while we decrement i
                     * pointer, to rerun the lines[i] which was just used as an
                     * indicator that no more lines are to be recombined.
                     */
                    if (buf.length() != 0) {
                        line = buf.toString();
                        buf.setLength(0);
                        i--;
                    }
                }

                if (0 == i) {
                    decodeFirstLine(line, record, timeStamp);
                    break;// 目前只需要第一行的参数，所以在这里就解析退出了。
                }

                String c[] = line.split(":", 2);

                if (c.length < 2) {
                    continue; // We need at least 2 sections or something is
                              // wrong
                }
                // 当程序执行到这里时，以成功解析 (2)头部
                // System.out.printf("HttpDecode : [%s]=[%s]\n", c[0], c[1]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
