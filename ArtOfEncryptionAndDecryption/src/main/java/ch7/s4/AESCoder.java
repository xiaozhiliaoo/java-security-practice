package ch7.s4;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public abstract class AESCoder {
    /**
     * 秘钥算法
     */
    public static final String KEY_ALGORITHM = "AES";
    /**
     * 加密/解密算法/工作模式/填充方式
     * Java7支持PKCS5PADDING填充方式
     * Bouncy Castle支持PKCS7Padding填充方式
     */
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    /**
     * 转换秘钥
     * @param key 二进制秘钥
     * @return Key 秘钥
     * @throws Exception
     */
    private static Key toKey(byte[] key) throws Exception {
        //实例化DES秘钥材料
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        return secretKey;
    }

    /**
     * 解密
     * @param data 待解密数据
     * @param key 秘钥
     * @return byte[] 解密数据
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        // 还原秘钥
        Key k = toKey(key);
        /**
         * 实例化
         * 使用PKCS7Padding填充方式，按如下方式实现
         * Cipher.getInstance(CIPHER_ALGORITHM, "BC")
         */
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //初始化， 设置为解密模式
        cipher.init(Cipher.DECRYPT_MODE, k);
        // 执行操作
        return cipher.doFinal(data);
    }

    /**
     *  加密
     * @param data 待加密数据
     * @param key 秘钥
     * @return byte[] 加密数据
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        //还原秘钥
        Key k = toKey(key);
        /**
         * 实例化
         * 使用PKCS7Padding填充方式，按如下方式实现
         * Cipher.getInstance(CIPHER_ALGORITHM, "BC");
         */
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //初始化，设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, k);
        // 执行操作
        return cipher.doFinal(data);
    }

    /**
     * 生成秘钥 <br>
     * @return byte[] 二进制秘钥
     * @throws Exception
     */
    public static byte[] initKey() throws Exception {
        // 实例化
        KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        // AES要求秘钥长度为128位，192位或256位
        kg.init(256);
        // 生成秘密秘钥
        SecretKey secretKey = kg.generateKey();
        // 获得秘钥的二进制编码形式
        return secretKey.getEncoded();
    }


    public static byte[] initKey(int keysize) throws Exception {
        if (keysize != 128 && keysize != 192 && keysize != 256) {
            throw new IllegalArgumentException("keysize: must be equal to 128, 192 or 256");
        }
        // 实例化
        KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        // AES要求秘钥长度为128位，192位或256位
        kg.init(keysize);
        // 生成秘密秘钥
        SecretKey secretKey = kg.generateKey();
        // 获得秘钥的二进制编码形式
        return secretKey.getEncoded();
    }
}
