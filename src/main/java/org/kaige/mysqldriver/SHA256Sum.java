package org.kaige.mysqldriver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class SHA256Sum {

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static byte[] getSalt() {
        String s = "4c4916023534584a696a760d3f774b112e4b2638";
        return HexFormat.of().parseHex(s);
    }

    private static byte[] mergeByteArray(byte[] one, byte[] two) {
        byte[] combined = new byte[one.length + two.length];

        System.arraycopy(one,0,combined,0         ,one.length);
        System.arraycopy(two,0,combined,one.length,two.length);
        return combined;
    }

    /*
        src == password clear text

        SHA2(src) => digest_stage1
        SHA2(digest_stage1) => digest_stage2
        SHA2(digest_stage2, m_rnd) => scramble_stage1
        XOR(digest_stage1, scramble_stage1) => scramble

        scramble == login request password
     */
    public static void main(String[] args) {
        encode("root", getSalt());
    }

    public static byte[] encode(String passwordText, byte[] salt) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] digest1 = digest.digest(
                passwordText.getBytes(StandardCharsets.UTF_8));
        System.out.println(bytesToHex(digest1)); // digest1

        digest.reset();
        byte[] encodedhash = digest.digest(digest1);
        System.out.println(bytesToHex(encodedhash)); // digest2

        digest.reset();
        byte[] combined = mergeByteArray(encodedhash, salt);
        encodedhash = digest.digest(combined);
        System.out.println(bytesToHex(combined)); // salt
        System.out.println(bytesToHex(encodedhash)); // digest2,rnd


        for (int i = 0; i < encodedhash.length; i++) {
            encodedhash[i] ^= digest1[i];
        }
        System.out.println(bytesToHex(encodedhash)); // password
        return encodedhash;
    }
}
