package ca.ubc.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.Random;
import java.util.Set;
import java.util.Map;
import java.util.*;
import java.nio.charset.*;

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

        if (verboseTracing) {
            System.out.print("\n\n");
            System.out.println("Query ID     "+ id + " " + node.getHostName() + " " + node.getType() + " --> " + server.getHostAddress());
        }
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
            if (verboseTracing) {
                System.out.print("\n\n");
                System.out.println("Query ID     "+ id + " " + node.getHostName() + " " + node.getType() + " --> " + server.getHostAddress());
            }       
            socket.send(requestPacket);
            socket.receive(responsePacket);
        }

        // for (int i = 0; i < response.length; i++) {
        //     System.out.print(Integer.toHexString(response[i] & 0xFF) + " ");
        // }
        // System.out.println();


        ByteBuffer responseMessage = ByteBuffer.wrap(response);
        return new DNSServerResponse(responseMessage, id);
    }

    // Call this method when encountering a pointer in the response. It will dereference each nested
    // pointer and store the values into the array. 
    private static void flattenPointersAndCollectBytes(ByteBuffer responseBuffer, byte offset, List<Byte> bytesArray) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(responseBuffer.array());
        DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);
        try {
            for (int i = 0; i < (offset & 0xFF); i++) {
                dataInputStream.readByte();
            }
            byte currentByte = dataInputStream.readByte();
            while(currentByte != (byte)0) {
                if (currentByte == (byte)0xc0) {
                    flattenPointersAndCollectBytes(responseBuffer, dataInputStream.readByte(), bytesArray);
                    break;
                } else {
                    bytesArray.add(currentByte);
                }
                currentByte = dataInputStream.readByte();
            }
        } catch (IOException e) {
            // TODO: does it do something here?
        }
    }


    // Given a list of bytes such as 03 77 77 77 02 65 34, convert them all into a domain
    // such as www.cs
    public static String convertBytesToFDQN(List<Byte> list) {
        String domain = "";
        if (list.isEmpty()) {
            return domain;
        }

        byte wordLength = list.get(0);
        for (int i = 0; i < list.size() && list.get(i) != 0; i++) {
            int currVal = i;
            for (int j = i+1; j < wordLength+currVal+1; j++) {
                domain += (char)list.get(j).byteValue();
                i++;
            }
            if (i < list.size()-1 && list.get(i+1) != 0) {
                domain += ".";
                wordLength = list.get(i+1);
            }
        }
        return domain;
    } 

    // Create a new ResourceRecord by extracting data from dataInputStream and the responseBuffer
    // @return the new ResourceRecord
    public static ResourceRecord createResourceRecord(DataInputStream dataInputStream, ByteBuffer responseBuffer) throws IOException {
        byte answerByte = dataInputStream.readByte();
        String name = "";
        if (answerByte == (byte)0xc0) {
            List<Byte> bytes = new ArrayList<>();
            flattenPointersAndCollectBytes(responseBuffer, dataInputStream.readByte(), bytes);
            name = convertBytesToFDQN(bytes);
        }
        short TYPE = dataInputStream.readShort();
        short CLASS = dataInputStream.readShort();
        int TTL = dataInputStream.readInt();
        int RDLENGTH = dataInputStream.readShort();

        // RDATA
        String textResult = "";
        InetAddress addr = null;
        if (RecordType.getByCode(TYPE) == RecordType.A || RecordType.getByCode(TYPE) == RecordType.AAAA) {
            byte[] ipAddr = new byte[RDLENGTH];
            for (int i = 0; i < RDLENGTH; i++) {
                ipAddr[i] = dataInputStream.readByte();
            }

            addr = InetAddress.getByAddress(ipAddr);
            ResourceRecord newRecord = new ResourceRecord(name, RecordType.getByCode(TYPE), TTL, addr);
            verbosePrintResourceRecord(newRecord, TYPE);
            return newRecord;
        } else if (RecordType.getByCode(TYPE) == RecordType.CNAME || RecordType.getByCode(TYPE) == RecordType.NS) {
            ArrayList<Byte> bytesArray = new ArrayList<>();

            for (int i = 0; i < RDLENGTH; i++) {
                byte currByte = dataInputStream.readByte();
                if (currByte == (byte)0xc0) {
                    byte offset = dataInputStream.readByte();
                    flattenPointersAndCollectBytes(responseBuffer, offset, bytesArray);
                    i++;
                } else {
                    bytesArray.add(currByte);
                }                            
            }
            textResult += convertBytesToFDQN(bytesArray);
            ResourceRecord newRecord = new ResourceRecord(name, RecordType.getByCode(TYPE), TTL, textResult);
            verbosePrintResourceRecord(newRecord, TYPE);
            return newRecord;
        } else if (RecordType.getByCode(TYPE) == RecordType.SOA) {
            ResourceRecord newRecord = new ResourceRecord(name, RecordType.getByCode(TYPE), TTL, "----");
            verbosePrintResourceRecord(newRecord, TYPE);
            return newRecord;
        }
        return null;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(responseBuffer.array());
        DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

        //return type
        Set<ResourceRecord> allRecords = new HashSet<>();

        // Header Section Flags
        int QR, OPCode, AA, TC, RD, RA, Z, RCODE = 0;
        int QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = 0;
        
        // Question Section
        short QTYPE, QCLASS;

        try {
            short responseID = dataInputStream.readShort();

            // transactionID and the ID from response must match or else we ignore this query
            if ((short)transactionID != responseID) {
                return allRecords;
            }

            // next short contains all the flags and status codes
            short secondHeaderRow = dataInputStream.readShort();
            // check flags using bit shifting
            QR = (secondHeaderRow & 0b1000000000000000) >>> 15;
            
            OPCode = (secondHeaderRow & 0b0111100000000000) >>> 11;
            
            // AA should be 1 to be authorative
            AA = (secondHeaderRow & 0b0000010000000000) >>> 10; // need to report
            TC = (secondHeaderRow & 0b0000001000000000) >>> 9;
            
            RD = (secondHeaderRow & 0b0000000100000000) >>> 8;
            RA = (secondHeaderRow & 0b0000000010000000) >>> 7;
            
            Z = (secondHeaderRow & 0b0000000001110000) >>> 4;
            RCODE = secondHeaderRow & 0b0000000000001111;
            if (QR != 1 || OPCode != 0 || TC != 0 || Z != 0 || RCODE != 0) {
                return allRecords;
            }

            // next rows of the DNS header
            QDCOUNT = dataInputStream.readShort();
            ANCOUNT = dataInputStream.readShort();
            NSCOUNT = dataInputStream.readShort();
            ARCOUNT = dataInputStream.readShort();

            // Read through the QUESTION
            while (dataInputStream.readByte() != 0) {}

            QTYPE = dataInputStream.readShort();
            QCLASS = dataInputStream.readShort();
            // now starts reading the DNS answer section
            
            // Iterate over all the RR's. Each iteration consists of looking at one
            // RR, and storing it into allRecords at the end.
            
            // Create all ANSWER RR's
            if (verboseTracing) {
                System.out.println("Response ID: " + responseID + " Authoritative = " + ((AA==1)?"true":"false"));
                System.out.println("  Answers (" + ANCOUNT + ")");
            }
            handleAllRecords(ANCOUNT, allRecords, AA, responseBuffer, dataInputStream, cache);

            // Create all AUTHORITY RR's
            if (verboseTracing) {
                System.out.println("  Nameservers (" + NSCOUNT + ")");
            }
            handleAllRecords(NSCOUNT, allRecords, AA, responseBuffer, dataInputStream, cache);

            // Create all ADDITIONAL RR's
            if (verboseTracing) {
                System.out.println("  Additional Information (" + ARCOUNT + ")");
            }
            handleAllRecords(ARCOUNT, allRecords, AA, responseBuffer, dataInputStream, cache);

        } catch (IOException e) {
            // TODO
        }

        return allRecords;
    }

    private static void handleAllRecords(
        int count, Set<ResourceRecord> allRecords, int isAuthoritative,
        ByteBuffer responseBuffer, DataInputStream dataInputStream, DNSCache cache) throws IOException{
        for (int i = 0; i < count; i++) {
            ResourceRecord record = createResourceRecord(dataInputStream, responseBuffer);
            if (record.getType() != RecordType.SOA) {
                allRecords.add(record);
            }
            if (isAuthoritative == 1) {
            //    for (ResourceRecord rr : allRecords) {
            //        if (rr.)
            //    }
            //    System.out.println();
                cache.addResult(record);
            }
        }
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing) {
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
        }
            
    }
}

