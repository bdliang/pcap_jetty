package org.jetty.demo;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PcapTcpLinkServlet extends HttpServlet {

    /**
     * ip filter访问这个类
     * */
    /**
     * serialVersionUID
     */
    private static final long serialVersionUID = 9195708116937048440L;

    private static Log log = LogFactory.getLog(PcapTcpLinkServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String result = req.getQueryString();
        System.out.println("\n" + result);
        try {
            // JSONObject json = JSONObject.fromObject(result);
            // int ip1 =
            // BasicUtils.IpStringToInt(json.getString("webserver_ip"));
            // int ip2 = BasicUtils.IpStringToInt(json.getString("datebaseIp"));
            System.out.println("aaaa");
            String[] ips = result.split(",");
            for (String str : ips) {
                System.out.println(str);
            }
            System.out.println("aaaa");
            // // int ip1 = BasicUtils.IpStringToInt("10.4.45.70");
            // // int ip2 = BasicUtils.IpStringToInt("0");
            // System.out.println(ip1 + " " + ip2);
            // long start = System.currentTimeMillis();
            // JSONArray jarray =
            // JSONArray.fromObject(ConnectionPairMap.getInstance().selectFirst(ip1,
            // ip2));
            // long end = System.currentTimeMillis();
            // System.out.println("seach time : " + (end - start));
            //
            // resp.getWriter().write(jarray.toString());
            resp.getWriter().write("-1");
            resp.getWriter().close();
        } catch (Exception e) {
            resp.getWriter().write("-1");
            e.printStackTrace();
        }

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // System.out.println("doPost");
        super.doPost(req, resp);
    }

    public String test() {
        // String url = "10.4.55.160:8080/oc/monitoring?part=info";
        String infoUrl = "http://10.4.55.160:8080/oc/monitoring?part=info";
        String result = test(infoUrl);
        return result;
    }

    public String test(String infoUrl) {
        String urlResult = getStringResultByUrl(infoUrl);
        // System.out.println(urlResult);
        // JsonParser jp = new JsonParser();
        // JsonObject jo = (JsonObject) jp.parse(urlResult);
        // String webServerIp = jo.get("webserver_ip").getAsString();
        // String dataBaseIp = jo.get("datebaseIp").getAsString();
        return urlResult;
    }

    private String getStringResultByUrl(String infoUrl) {
        String result = null;
        HttpGet request = null;
        HttpClient client = null;
        try {
            client = new DefaultHttpClient();
            client.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 30000);// 连接时间
            client.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT, 30000);// 数据传输时间
            // 生成request
            request = new HttpGet(new URI(infoUrl));
            request.setHeader("Connection", "close");
            HttpResponse response = null;
            // 获取response
            response = client.execute(request);
            response.setHeader("Connection", "close");
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode >= 400) {
                return null;
            }
            // 获取实体
            HttpEntity entity = response.getEntity();
            // 实体解析成String
            result = EntityUtils.toString(entity);
        } catch (ClientProtocolException e) {
            log.error("ClientProtocolException [" + infoUrl + "]", e);
        } catch (IOException e) {
            log.error("IOException [" + infoUrl + "]", e);
        } catch (ParseException e) {
            log.error("ParseException [" + infoUrl + "]", e);
        } catch (Exception e) {
            log.error(e.getMessage());
        } finally {
            if (request != null) {
                // 释放连接
                request.abort();
            }
        }
        return result;
    }
}
