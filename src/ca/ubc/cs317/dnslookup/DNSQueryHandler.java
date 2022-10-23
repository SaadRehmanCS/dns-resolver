package ca.ubc.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.Random;
import java.util.Set;

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
        // TODO (PART 1): Implement this
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

