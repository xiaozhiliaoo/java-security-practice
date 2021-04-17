package org.lili.security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesUtils {

    private AesUtils() {
        throw new AssertionError("No org.lili.security.AesUtils instances for you!");
    }

    //初始化向量，aes 16位
    private static final String INIT_VECTOR = "cccc";

    private static final String password = "cccc";

    //二进制转变为16进制
    private static String parseByte2HexStr(byte[] buf) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    //将16进制转变为二进制
    private static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }


    //加密
    public static String codeJiami(String content) {
        try {
            return encrypt(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //解密
    public static String codeJiemi(String content) {
        try {
            return decrypt(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //加密
    public static String encrypt(String content) throws Exception {
        return encrypt(content, password);
    }


    public static String encrypt(String content, String pwd) throws Exception {
        String keyWord = addSuffix(pwd);
        SecretKeySpec key = new SecretKeySpec(keyWord.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(INIT_VECTOR.getBytes()));
        byte[] encryptedData = cipher.doFinal(content.getBytes("UTF-8"));
        return parseByte2HexStr(encryptedData);
    }


    //解密
    public static String decrypt(String content) throws Exception {
        return decrypt(content, password);
    }

    public static String decrypt(String content, String pwd) throws Exception {
        String keyWord = addSuffix(pwd);
        byte[] contentBytes = parseHexStr2Byte(content);
        SecretKeySpec key = new SecretKeySpec(keyWord.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(INIT_VECTOR.getBytes()));
        byte[] result = cipher.doFinal(contentBytes);
        return new String(result, "UTF-8");
    }

    private static String addSuffix(String key) {
        int len = key.length();
        if (len >= 16) {
            return key;
        }
        for (int i = 0; i < 16 - len; i++) {
            key += "=";
        }
        return key;
    }
}