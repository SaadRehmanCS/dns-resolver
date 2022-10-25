package ca.ubc.cs317.dnslookup;

import java.io.*;
<<<<<<< HEAD
import java.io.DataInputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
=======
import java.net.*;
import java.nio.*;
>>>>>>> master
import java.util.Random;
import java.util.Set;
import java.util.Map;
import java.util.*;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(outputStream);

        short id = (short)random.nextInt(65535);        
        // HEADER
        // -----------------
        // ID
        dataStream.writeShort(id);
        // FLAGS
        dataStream.writeShort(0);
        // QDCOUNT
        dataStream.writeShort(1);
        // ANCOUNT
        dataStream.writeShort(0);
        // NSCOUNT
        dataStream.writeShort(0);
        // ARCOUNT
        dataStream.writeShort(0);

        // QUESTION
        // -----------------
        // QNAME
        String[] labels = node.getHostName().split("\\.");
        for (int i = 0; i < labels.length; i++) {
            dataStream.writeByte(labels[i].length());
            for (int j = 0; j < labels[i].length(); j++) {
                dataStream.writeByte((byte)labels[i].charAt(j));
            }
        }
        // Null-terminate the qname with 0 byte
        dataStream.writeByte(0);
        // QTYPE
        dataStream.writeShort((short)node.getType().getCode());
        // QCLASS
        dataStream.writeShort(1);

        // Convert datastream to byte array
        message = outputStream.toByteArray();

        // Send the query
        DatagramPacket requestPacket = new DatagramPacket(message, message.length, server, DEFAULT_DNS_PORT);
        socket.send(requestPacket);

        // Should receive query here
        byte[] response = new byte[1024];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        try {
            socket.receive(responsePacket);
        } catch (SocketTimeoutException e) {
            // If the query times out, re-send it one more time before failing
            socket.send(requestPacket);
            socket.receive(responsePacket);
        }
        
        ByteBuffer responseMessage = ByteBuffer.wrap(response);
        return new DNSServerResponse(responseMessage, id);
    }

    private static Charset charset = Charset.forName("US-ASCII");

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) throws IOException{
        // TODO (PART 1): Implement this
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(responseBuffer.array());
        DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

        // Header Section Flags
        int QR, OPCode, AA, TC, RD, RA, Z, RCODE = 0;
        int QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = 0;
        
        // Question Section
        String QNAME = "";
        short QTYPE, QCLASS;

        // Answer Section
        // NAME TYPE CLASS TTL RDLENGTH RDATA PREFERENCE EXCHANGE

        try {
            // first two bytes reads the qid   
            // String QIDHex = Short.toString(dataInputStream.readShort());
            // int QIDint = Integer.parseInt(QIDHex, 16);
            // String QID = Integer.toBinaryString(QIDint);     // compare with 16bits instead
            int QID = dataInputStream.readShort();
            // we need to check the qid 
            // if (QID.equals(transactionID)) {
            if (((QID & 0b1111111111111111) == transactionID) && (byteArrayInputStream.available() < 1025)) {    
                // next short contains all the flags and status codes
                short secondHeaderRow = dataInputStream.readShort();
                // check flags using bit shifting
                QR = (secondHeaderRow & 0b1000000000000000) >>> 15;
                if (QR != 1) {
                    // error, should be a response 
                }
                OPCode = (secondHeaderRow & 0b0111100000000000) >>> 11;
                if (OPCode != 0) {
                    // error, should be zero        
                }
                // AA should be 1 to be authorative
                AA = (secondHeaderRow & 0b0000010000000000) >>> 10; // need to report
                TC = (secondHeaderRow & 0b0000001000000000) >>> 9;
                if (TC != 0) {
                    // exit and return an error
                }
                RD = (secondHeaderRow & 0b0000000100000000) >>> 8;
                RA = (secondHeaderRow & 0b0000000010000000) >>> 7;
                if (RA != 1) {
                    // exit and return an error
                }
                Z = (secondHeaderRow & 0b0000000001110000) >>> 4;
                if (Z != 0) {
                   // not supposed to be anything but 0
                }
                RCODE = secondHeaderRow & 0b0000000000001111;
                if (RCODE == 0) { // 0b0000000000000000
                    // no error, continue        
                } else if (RCODE == 1) { // 0b0000000000000001
                    // format error
                } else if (RCODE == 2) { // 0b0000000000000010
                    // server failure
                } else if (RCODE == 3) { // 0b0000000000000011
                    // name error
                } else if (RCODE == 4) { // 0b0000000000000100
                    // not implemented error
                } else if (RCODE == 5) { // 0b0000000000000101
                    // refused error
                } else {
                    // reserved 
                }
                
                // next rows of the DNS header
                QDCOUNT = dataInputStream.readShort();
                ANCOUNT = dataInputStream.readShort();
                NSCOUNT = dataInputStream.readShort();
                ARCOUNT = dataInputStream.readShort();
                
                // now start reading the DNS question section
                int len;
                while ((len = dataInputStream.readByte()) != 0) {
                    byte[] domain = new byte[len];
                    for (int i = 0; i < len; i++) {
                        domain[i] = dataInputStream.readByte();
                    }
                    QNAME = new String(domain, charset); // need to change
                }
                QTYPE = dataInputStream.readShort();
                QCLASS = dataInputStream.readShort();

                // now starts reading the DNS answer section
                // name_being_looked_up  ADDRESS_TYPE  TTL  IP_address
                Map<String, String> domainToIp = new HashMap<>();
                byte answerByte = dataInputStream.readByte();
                int c0bits = (answerByte & 0b11000000) >>> 6;
                ByteArrayOutputStream label = new ByteArrayOutputStream();
                
                for (int i = 0; i < ANCOUNT; i++) {
                    if(c0bits == 3) {
                        byte currentByte = dataInputStream.readByte();
                        boolean stop = false;
                        byte[] newArray = Arrays.copyOfRange(responseBuffer.array(), currentByte, responseBuffer.array().length);
                        DataInputStream sectionDataInputStream = new DataInputStream(new ByteArrayInputStream(newArray));
                        ArrayList<Integer> RDATA = new ArrayList<>();
                        ArrayList<String> DOMAINS = new ArrayList<>();
                        while(!stop) {
                            byte nextByte = sectionDataInputStream.readByte();
                            if(nextByte != 0) {
                                byte[] currentLabel = new byte[nextByte];
                                for (int j = 0; j < nextByte; j++) {
                                    currentLabel[j] = sectionDataInputStream.readByte();
                                }
                                label.write(currentLabel);
                            } else {
                                stop = true;
                                short TYPE = dataInputStream.readShort();
                                short CLASS = dataInputStream.readShort();
                                int TTL = dataInputStream.readInt();
                                int RDLENGTH = dataInputStream.readShort();
                                for(int s = 0; s < RDLENGTH; s++) {
                                    int nx = dataInputStream.readByte() & 255;
                                    RDATA.add(nx);
                                }
                            }
                
                            DOMAINS.add(label.toString(charset));
                            label.reset();
                        }
                
                        StringBuilder ip = new StringBuilder();
                        StringBuilder domainSb = new StringBuilder();
                        for (Integer ipPart:RDATA) {
                            ip.append(ipPart).append(".");
                        }
                
                        for (String domainPart:DOMAINS) {
                            if(!domainPart.equals("")) {
                                domainSb.append(domainPart).append(".");
                            }
                        }
                        String domainFinal = domainSb.toString();
                        String ipFinal = ip.toString();
                        domainToIp.put(ipFinal.substring(0, ipFinal.length()-1), domainFinal.substring(0, domainFinal.length()-1));
                        
                    } else if (c0bits == 0) {
                        // System.out.println("It's a label");
                    }
                
                    c0bits = dataInputStream.readByte();
                    c0bits = (c0bits & 0b11000000) >>> 6;
                }
                
                cache.forEachNode(null);
                
                // domainToIp.forEach((key, value) -> System.out.println(key + " : " + value));
            } else {
                // transactionID doesn't match
            }
                
        } catch (IOException e) {
            throw new IOException(e);
        }
        // Header Section Variables
                // boolean AA = false;
                // boolean TC = false;
                // boolean RD = false;
                // boolean RA = false;
                // int QDCOUNT = 0;
                // int ANCOUNT = 0;
                // int NSCOUNT = 0;
                // int ARCOUNT = 0;
        // Question Section Variables
                // String QNAME = "";
                // if (responseBuffer.hasArray()) {
            // Check Query ID matches with transactionID
                    // String queryIDCheck = Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt());
                    // if(queryIDCheck.equals(valueOf(transactionID))) {
                // if it matches we move on to the 3rd byte
                //  0 |0  0  0  0| 0| 0| 0|
                // QR | OP CODE  |AA|TC|RD|

                        // String thridByteBinary = Integer.toBinarySrting(responseBuffer.getInt());

                // check QR, query (0) or response (1)
                        // if ...3(thridByteBinary.charAt(0) == 1) {
                    // enters if it is a response 
                    
                    // check Opcode, should always be 0 (standard query) 
                            // if ((thirdByteBinary.chartAt(1) == 0) && (thirdByteBinary.chartAt(2) == 0) && (thirdByteBinary.chartAt(3) == 0) && (thirdByteBinary.chartAt(4) == 0)) {
                        // it is a standard query 

                        // check AA bit, authorative (1)
                                // if (thirdByteBinary.chartAt(5) == 1) {
                                //     AA = true;
                                // }
                        // check TC bit, response is truncated (1)
                                // if (thirdByteBinary.chartAt(6) == 1) {
                                //     TC = true;
                                // }
                        // check RD bit, if a query wants the name server to try to answer the question by initiating a recursive query (1)
                                // if (thirdByteBinary.chartAt(7) == 1) {
                                //     RC = true;
                                // }
                            // } else {
                        // OPCode is not a stadard query
                            // }

                    // now we compute the 4th byte
                    //  0 |0  0  0 |0  0  0  0|
                    // RA |   Z    |  R CODE  |

                            // String fourthByteBinary = Integer.toBinarySrting(responseBuffer.getInt());

                    // check RA bit, recursion available (1)
                            // if (fourthByteBinary.chartAt(0) == 1) {
                            //     RA = true;
                            // } else {
                        // error
                            // }

                    //check Z, must all be 0 for query and response 
                            // if (!((fourthByteBinary.chartAt(1) == 0) && (fourthByteBinary.chartAt(2) == 0) && (fourthByteBinary.chartAt(3) == 0))) {
                            //     // return with error as the bits should only be (0 0 0 0)
                            // }

                    //check RCODE
                            // if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 1)) {
                            //     // return with format error (0 0 0 1) i.e. the name server was unable to interpret the query
                            // }
                            // if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 1) && (fourthByteBinary.chartAt(7) == 0)) {
                            //     // return with server faliure (0 0 1 0) i.e. the name server was unable to process this query due to a problem with the name server
                            // }
                            // if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 1) && (fourthByteBinary.chartAt(7) == 1)) {
                            //     // return with name error (0 0 1 1) i.e. the name server was unable to process this query due to a problem with the name server
                            // }
                            // if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 1) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 0)) {
                            //     // return with not implemented error (0 1 0 0) i.e. the name server does not support the requested kind of query
                            // }
                            // if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 1) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 1)) {
                            //     // return refused (0 1 0 1) i.e. the name server refuses to perform the specified operation for policy reasons
                            // }
                            // if (!((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 0))) {
                            //     // reserved for future use
                            //     // if no RCODE if statements are caught then there are no errors
                            // }

                    // now the 5th and 6th byte combined gives the QDCOUNT number, number of entries in the question section
                            // QDCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);

                    // now the 7th and 8th byte combined gives the ANCOUNT number, number of RRs in the answer section                 
                            // ANCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);
                    
                    // now the 9th and 10th byte combined gives the NSCOUNT number, number of name server RRs in the authority records section                
                            // NSCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);
                    
                    // now the 11th and 12th byte combined gives the ARCOUNT number, number of RRs in the additional records section               
                            // ARCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);
                    
                    // **reading the header section finshes**
                    
                    // now comes the DNS question section
                            // int firstQNAMEByte = responseBuffer.getInt();

                        // } else {
                    // it is a query (0), QR = 0
                        // }

                // retDec = new String(responseBuffer.array(), charset);
                    // } else {
                // transaction id does not match so should return an error
                //     }
                //}
        return null;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

