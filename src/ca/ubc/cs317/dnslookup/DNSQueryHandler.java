package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
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
        // TODO (PART 1): Implement this
        return null;
    }

    // private static Charset charset = Charset.forName("US-ASCII");

    private static int hexToDecimal(String hex) {  
        String hstring = "0123456789ABCDEF";
        hex = hex.toUpperCase();
        int num = 0;
        for (int i = 0; i < hex.length(); i++)  {  
            char ch = hex.charAt(i);
            int n = hstring.indexOf(ch);
            num = 16*num + n;
	    }
	    return num;
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
        // Header Section Variables
        boolean AA = false;
        boolean TC = false;
        boolean RD = false;
        boolean RA = false;
        int QDCOUNT = 0;
        int ANCOUNT = 0;
        int NSCOUNT = 0;
        int ARCOUNT = 0;
        // Question Section Variables
        String QNAME = "";
        if (responseBuffer.hasArray()) {
            // Check Query ID matches with transactionID
            String queryIDCheck = Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt());
            if(queryIDCheck.equals(valueOf(transactionID))) {
                // if it matches we move on to the 3rd byte
                //  0 |0  0  0  0| 0| 0| 0|
                // QR | OP CODE  |AA|TC|RD|

                String thridByteBinary = Integer.toBinarySrting(responseBuffer.getInt());

                // check QR, query (0) or response (1)
                if (thridByteBinary.charAt(0) == 1) {
                    // enters if it is a response 
                    
                    // check Opcode, should always be 0 (standard query) 
                    if ((thirdByteBinary.chartAt(1) == 0) && (thirdByteBinary.chartAt(2) == 0) && (thirdByteBinary.chartAt(3) == 0) && (thirdByteBinary.chartAt(4) == 0)) {
                        // it is a standard query 

                        // check AA bit, authorative (1)
                        if (thirdByteBinary.chartAt(5) == 1) {
                            AA = true;
                        }
                        // check TC bit, response is truncated (1)
                        if (thirdByteBinary.chartAt(6) == 1) {
                            TC = true;
                        }
                        // check RD bit, if a query wants the name server to try to answer the question by initiating a recursive query (1)
                        if (thirdByteBinary.chartAt(7) == 1) {
                            RC = true;
                        }
                    } else {
                        // OPCode is not a stadard query
                    }

                    // now we compute the 4th byte
                    //  0 |0  0  0 |0  0  0  0|
                    // RA |   Z    |  R CODE  |

                    String fourthByteBinary = Integer.toBinarySrting(responseBuffer.getInt());

                    // check RA bit, recursion available (1)
                    if (fourthByteBinary.chartAt(0) == 1) {
                        RA = true;
                    } else {
                        // error
                    }

                    //check Z, must all be 0 for query and response 
                    if (!((fourthByteBinary.chartAt(1) == 0) && (fourthByteBinary.chartAt(2) == 0) && (fourthByteBinary.chartAt(3) == 0))) {
                        // return with error as the bits should only be (0 0 0 0)
                    }

                    //check RCODE
                    if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 1)) {
                        // return with format error (0 0 0 1) i.e. the name server was unable to interpret the query
                    }
                    if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 1) && (fourthByteBinary.chartAt(7) == 0)) {
                        // return with server faliure (0 0 1 0) i.e. the name server was unable to process this query due to a problem with the name server
                    }
                    if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 1) && (fourthByteBinary.chartAt(7) == 1)) {
                        // return with name error (0 0 1 1) i.e. the name server was unable to process this query due to a problem with the name server
                    }
                    if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 1) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 0)) {
                        // return with not implemented error (0 1 0 0) i.e. the name server does not support the requested kind of query
                    }
                    if ((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 1) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 1)) {
                        // return refused (0 1 0 1) i.e. the name server refuses to perform the specified operation for policy reasons
                    }
                    if (!((fourthByteBinary.chartAt(4) == 0) && (fourthByteBinary.chartAt(5) == 0) && (fourthByteBinary.chartAt(6) == 0) && (fourthByteBinary.chartAt(7) == 0))) {
                        // reserved for future use
                        // if no RCODE if statements are caught then there are no errors
                    }

                    // now the 5th and 6th byte combined gives the QDCOUNT number, number of entries in the question section
                    QDCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);

                    // now the 7th and 8th byte combined gives the ANCOUNT number, number of RRs in the answer section                 
                    ANCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);
                    
                    // now the 9th and 10th byte combined gives the NSCOUNT number, number of name server RRs in the authority records section                
                    NSCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);
                    
                    // now the 11th and 12th byte combined gives the ARCOUNT number, number of RRs in the additional records section               
                    ARCOUNT = Interget.parseInt(Integer.toBinarySrting(responseBuffer.getInt()) + Integer.toBinarySrting(responseBuffer.getInt()),2);
                    
                    // **reading the header section finshes**
                    
                    // now comes the DNS question section
                    int firstQNAMEByte = responseBuffer.getInt();

                } else {
                    // it is a query (0), QR = 0
                }

                // retDec = new String(responseBuffer.array(), charset);
            } else {
                // transaction id does not match so should return an error
            }
        }
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

