/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package pcap.myprotocol;

import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

@Header(suite = ProtocolSuite.TCP_IP)
public class SoapTest extends AbstractMessageHeader {

    /** Constant numerical ID assigned to this protocol. */
    public final static int ID = JProtocol.HTTP_ID;

    static {
        try {
            JRegistry.register(SoapTest.class);
        } catch (RegistryHeaderErrors e) {
            e.printStackTrace();
        }
    }

    public enum ContentType {

        /** Soap 1.1 */
        SOAP1_1("application/soap+xml"),

        /** Soap 1.2 */
        SOAP1_2("text/xml"),

        /** The OTHER. */
        OTHER, ;

        public static ContentType parseContentType(String type) {
            if (type == null) {
                return OTHER;
            }

            for (ContentType t : values()) {
                if (t.name().equalsIgnoreCase(type)) {
                    return t;
                }

                for (String m : t.magic) {
                    if (type.startsWith(m)) {
                        return t;
                    }
                }
            }

            return OTHER;
        }

        private final String[] magic;

        private String description;

        /**
         * Instantiates a new content type.
         * 
         * @param magic
         *            the magic
         */
        private ContentType(String... magic) {
            this.magic = magic;
        }

        private ContentType(String description) {
            this.description = description;
            this.magic = null;
        }

        public String toString() {
            return this.description;
        }
    }

    /**
     * HTTP Request fields.
     * 
     * @author Mark Bednarczyk
     * @author Sly Technologies, Inc.
     */
    @Field
    public enum Request {

        /** The Date. */
        Date,

        /** The Host. */
        Host,

        /** The Request method. */
        RequestMethod,

        /** The Request url. */
        RequestUrl,

        /** The Request version. */
        RequestVersion,

        /** The Content_ length. */
        Content_Length,

        /** The Content_ type. */
        Content_Type,

        /** The Soap action for soap1.1 */
        SOAPAction,
    }

    /**
     * HTTP Response fields.
     * 
     * @author Mark Bednarczyk
     * @author Sly Technologies, Inc.
     */
    @Field
    public enum Response {

        /** The Age. */
        Age,

        /** The Content_ type. */
        Content_Type,

        /** The Request version. */
        RequestVersion,

        /** The Response code. */
        ResponseCode,

        /** The Response code msg. */
        ResponseCodeMsg,
    }

    /**
     * Content type.
     * 
     * @return the string
     */
    public String contentType() {
        return fieldValue(Response.Content_Type);
    }

    public String soapAction() {
        return fieldValue(Request.SOAPAction);
    }

    public boolean isSoapProtocol() {
        if (hasContentType()) {
            if (-1 != contentType().indexOf(ContentType.SOAP1_1.toString()) && this.hasField("SOAPAction")) {
                return true;
            } else if (-1 != contentType().indexOf(ContentType.SOAP1_2.toString())) {
                return true;
            }
        }
        return false;
    }
    /**
     * Content type enum.
     * 
     * @return the content type
     */
    public ContentType contentTypeEnum() {
        return ContentType.parseContentType(contentType());
    }

    /**
     * Decode first line.
     * 
     * @param line
     *            the line
     * @see org.jnetpcap.packet.AbstractMessageHeader#decodeFirstLine(java.lang.String)
     */
    @Override
    protected void decodeFirstLine(String line) {
        // System.out.printf("#%d Http::decodeFirstLine line=%s\n", getPacket()
        // .getFrameNumber(), line);
        String[] c = line.split(" ");
        if (c.length < 3) {
            return; // Can't parse it
        }

        if (c[0].startsWith("HTTP")) {
            super.setMessageType(MessageType.RESPONSE);

            super.addField(Response.RequestVersion, c[0], line.indexOf(c[0]));
            super.addField(Response.ResponseCode, c[1], line.indexOf(c[1]));
            super.addField(Response.ResponseCodeMsg, c[2], line.indexOf(c[2]));

        } else {
            super.setMessageType(MessageType.REQUEST);

            super.addField(Request.RequestMethod, c[0], line.indexOf(c[0]));
            super.addField(Request.RequestUrl, c[1], line.indexOf(c[1]));
            super.addField(Request.RequestVersion, c[2], line.indexOf(c[2]));
        }
    }

    /**
     * Field value.
     * 
     * @param field
     *            the field
     * @return the string
     */
    public String fieldValue(Request field) {
        return super.fieldValue(String.class, field);
    }

    /**
     * Field value.
     * 
     * @param field
     *            the field
     * @return the string
     */
    public String fieldValue(Response field) {
        return super.fieldValue(String.class, field);
    }

    /**
     * Checks for content.
     * 
     * @return true, if successful
     */
    public boolean hasContent() {
        return hasField(Response.Content_Type) || hasField(Request.Content_Type);
    }

    /**
     * Checks for content type.
     * 
     * @return true, if successful
     */
    public boolean hasContentType() {
        return hasField(Response.Content_Type);
    }

    /**
     * Checks for field.
     * 
     * @param field
     *            the field
     * @return true, if successful
     */
    public boolean hasField(Request field) {
        return super.hasField(field);
    }

    /**
     * Checks for field.
     * 
     * @param field
     *            the field
     * @return true, if successful
     */
    public boolean hasField(Response field) {
        return super.hasField(field);
    }

    /**
     * Checks if is response.
     * 
     * @return true, if is response
     */
    public boolean isResponse() {
        return getMessageType() == MessageType.RESPONSE;
    }

    /**
     * Gets the raw header instead of reconstructing it.
     * 
     * @return original raw header
     */
    public String header() {
        return super.rawHeader;
    }
}
