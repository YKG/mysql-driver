package org.kaige.mysqldriver;

import java.io.*;
import java.net.Socket;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;

public class MySQLDriver {


    public static final String ip = "127.0.0.1";
//    public static final String ip = "192.168.0.106";
    public static final int port = 3306;
    public static final String user = "ykg";
    public static final String pass = "root";


    private long readInt3(InputStream is) {
        int b0, b1, b2;
        try {
            b0 = (byte) is.read();
            b1 = (byte) is.read();
            b2 = (byte) is.read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return b0 + (b1 << 8) + (b2 << 16);
    }

    private long readInt1(InputStream is) {
        int b0;
        try {
            b0 = (byte) is.read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return b0;
    }

    private long getPacketLength(InputStream is) {
        return readInt3(is);
    }

    private long getSeqId(InputStream is) {
        return readInt1(is);
    }

    private byte[] getSalt(ByteBuffer serverGreeting) {
        ByteBuffer salt1 = serverGreeting.slice(18, 8);
        ByteBuffer salt2 = serverGreeting.slice(18 + 16 + 8 + 3, 12);
        int salt1Len = salt1.remaining();
        int salt2Len = salt2.remaining();
        byte[] arr = new byte[salt1Len + salt2Len];
        salt1.get(arr, 0, salt1Len);
        salt2.get(arr, salt1Len, salt2Len);
        return arr;
    }

    private ByteBuffer dumpPayload(InputStream is, long len) {
        ByteBuffer buffer = ByteBuffer.allocate((int) len);
        for (int i = 0; i < len; i++) {
            int b0;
            try {
                b0 = (byte) is.read();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            buffer.put((byte) b0);
            if (i > 0 && (i % 16 == 0)) {
                System.out.println();
            }
            System.out.printf("%02x ", b0 & 0xff);
        }

        return buffer;
    }


    private void writePacketLen(OutputStream os, int len) {
        try {
            os.write(new byte[]{(byte) (len & 0xff)});
            os.write(new byte[]{(byte) ((len >> 8) & 0xff)});
            os.write(new byte[]{(byte) ((len >> 16) & 0xff)});
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writePacketNumber(OutputStream os, int seqId) {
        try {
            os.write(new byte[]{(byte) (seqId & 0xff)});
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] encodePassword(byte[] salt) {
        return SHA256Sum.encode(pass, salt);
    }

    private void sendLoginRequest(OutputStream os, byte[] salt) {
        writePacketLen(os, 206);
        writePacketNumber(os, 1);
        byte[] encodedPassword = encodePassword(salt);
// 85a6ff1900000001ff0000000000000000000000000000000000000000000000796b6700203b62f3470390ca04e0168fe96f558429a38b1c931c52f7ad0adeb43f80ba2df263616368696e675f736861325f70617373776f72640072045f706964053938323235095f706c6174666f726d067838365f3634035f6f73054c696e75780c5f636c69656e745f6e616d65086c69626d7973716c076f735f7573657203796b670f5f636c69656e745f76657273696f6e06382e302e32390c70726f6772616d5f6e616d65056d7973716c
//        String s = "85a6ff1900000001ff0000000000000000000000000000000000000000000000796b6700203b62f3470390ca04e0168fe96f558429a38b1c931c52f7ad0adeb43f80ba2df263616368696e675f736861325f70617373776f72640072045f706964053938323235095f706c6174666f726d067838365f3634035f6f73054c696e75780c5f636c69656e745f6e616d65086c69626d7973716c076f735f7573657203796b670f5f636c69656e745f76657273696f6e06382e302e32390c70726f6772616d5f6e616d65056d7973716c";

        String s = "85a6ff1900000001ff0000000000000000000000000000000000000000000000796b670020";
        //s += "3b62f3470390ca04e0168fe96f558429a38b1c931c52f7ad0adeb43f80ba2df2";
        s += HexFormat.of().formatHex(encodedPassword);
        s += "63616368696e675f736861325f70617373776f72640072045f706964053938323235095f706c6174666f726d067838365f3634035f6f73054c696e75780c5f636c69656e745f6e616d65086c69626d7973716c076f735f7573657203796b670f5f636c69656e745f76657273696f6e06382e302e32390c70726f6772616d5f6e616d65056d7973716c";

        writeHexString(os, s);
    }

    private void writeHexString(OutputStream os, String s) {
        System.out.println(s);
        for (int i = 0; i < s.length(); i+=2) {
            try {
                os.write(new byte[]{(byte) (Integer.parseInt(s.substring(i, i+2), 16) & 0xff)});
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private Socket conn() {
        Socket clientSocket = null;
        try {
            clientSocket = new Socket(ip, port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        InputStream is = null;
        try {
            is = clientSocket.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        long len = getPacketLength(is);
        System.out.printf("%x\n", len);
        System.out.printf("%x\n", getSeqId(is));
        ByteBuffer buffer = dumpPayload(is, len);
        System.out.println(HexFormat.of().formatHex(getSalt(buffer)));

        // send client login request to server
        OutputStream out = null;
        try {
            out = clientSocket.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        sendLoginRequest(out, getSalt(buffer));

        return clientSocket;
    }

    private void sendQuery(Socket clientSocket, String query) {
        BufferedOutputStream os;
        try {
            os = new BufferedOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        writePacketLen(os, query.length() + 3);
        writePacketNumber(os, 0);

        // 0x03 COM_QUERY
        // 0X00 QUERY ATTRS COUNT
        // 0X01 nsets == 1. fixed value
        String s = "030001";
        writeHexString(os, s);
        try {
            os.write(query.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            os.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private void sendQuit(Socket clientSocket) {
        BufferedOutputStream os;
        try {
            os = new BufferedOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        writePacketLen(os, 1);
        writePacketNumber(os, 0);
        writePacketNumber(os, ServerCommand.COM_QUIT.ordinal());

        try {
            os.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void dumpResponse(Socket clientSocket) {
        System.out.println("---------------------- dumpResp");
        BufferedInputStream is;
        try {
            is = new BufferedInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        long len = getPacketLength(is);
        System.out.printf("%x\n", len);
        System.out.printf("%x\n", getSeqId(is));
        ByteBuffer buffer = dumpPayload(is, len);
        System.out.println(buffer);
    }

    private long readLength(BufferedInputStream is) {
        int code = (int) (readInt1(is) & 0xff);
        int len = switch (code) {
            case 0xfc -> 2;
            case 0xfd -> 3;
            case 0xfe -> 8;
            default -> 1;
        };
        int[] arr = new int[len];
        for (int i = len - 1; i >= 0; i--) {
            arr[i] = (int) (readInt1(is) & 0xff);
        }
        long val = 0;
        for (int i = len - 1; i >= 0; i--) {
            val += ((long) arr[i] << (i * 8));
        }
        return val;
    }

    private void dumpQueryResponse(Socket clientSocket) {
        System.out.println("---------------------- dumpQueryResp");
        BufferedInputStream is;
        try {
            is = new BufferedInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        long len = getPacketLength(is);
        System.out.printf("%x\n", len);
        System.out.printf("%x\n", getSeqId(is));

        long fieldsCount = 0;
        if (len == 1) {
            int code = (int) (readInt1(is) & 0xff);
            switch (code) {
                case 0x00:
                    // ok (eg. set autocommit = 1)
                    throw new RuntimeException("TODO never reach? ok");
                case 0xfb:
                    throw new RuntimeException("TODO 0xfb more data LOCAL INFILE Request");
                case 0xff:
                    // err (eg. xxx)
                    throw new RuntimeException("TODO never reach? err");
                default:
                    fieldsCount = code;
            }
        } else {
            int code = (int) (readInt1(is) & 0xff);
            switch (code) {
                case 0x00:
                    // ok (eg. set autocommit = 1)
                    dumpPayload(is, len - 1);
                    break;
                case 0xff:
                    dumpPayload(is, len - 1);
                    break;
            }
            fieldsCount = readLength(is);
        }
        System.out.println("Field Count: " + fieldsCount);

        for (int i = 0; i < fieldsCount; i++) {
            // get field desc
            System.out.printf("Field[%d]:\n ", i);
            long packetLength = getPacketLength(is);
            System.out.printf("%x\n", packetLength);
            System.out.printf("%x\n", getSeqId(is));
            ByteBuffer buffer = dumpPayload(is, packetLength);
            System.out.println(buffer);
        }

        for (int i = 0; ; i++) {
            long packetLength = getPacketLength(is);
            System.out.printf("%x\n", packetLength);
            System.out.printf("%x\n", getSeqId(is));
            ByteBuffer buffer = dumpPayload(is, packetLength);
            if (buffer.get(0) == (byte) 0xfe) { // EOF packet
                System.out.printf(" <- EOF[%d]:\n ", i);
                break;
            }
            System.out.printf(" <- Row[%d]:\n ", i);
//            System.out.println(buffer);
        }
    }

    public static void main(String[] args) {
        System.out.println("mysql");
        MySQLDriver driver = new MySQLDriver();
        Socket clientSocket = driver.conn();
        driver.dumpResponse(clientSocket);
        driver.dumpResponse(clientSocket);
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        driver.sendQuery(clientSocket, "select user()");
        driver.dumpQueryResponse(clientSocket);
        driver.sendQuery(clientSocket, "select User,Host from mysql.user");
        driver.dumpQueryResponse(clientSocket);
        driver.sendQuery(clientSocket, "set autocommit = 1");
        driver.dumpQueryResponse(clientSocket);
        driver.sendQuit(clientSocket);
    }
}
