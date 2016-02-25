package org.jetty.demo;

import pcap.constant.BasicConstants;
import pcap.table.TcpTable;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PcapTcpLinkServlet extends HttpServlet {

    /**
     * 拓扑图ip过滤， 访问这个类
     * */
    /**
     * serialVersionUID
     */
    private static final long serialVersionUID = 9195708116937048440L;

    // private static Log log = LogFactory.getLog(PcapTcpLinkServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String ipString = req.getQueryString();
        // System.out.println("\n" + ipString);
        try {
            String result = TcpTable.getInstance().selectIpWithHttp(ipString);
            // System.out.println("\n" + result);
            resp.getWriter().write(result);
        } catch (Exception e) {
            resp.getWriter().write(BasicConstants.NULL_JSON_RETURN);
            e.printStackTrace();
        } finally {
            resp.getWriter().close();
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // System.out.println("doPost");
        super.doPost(req, resp);
    }
}
