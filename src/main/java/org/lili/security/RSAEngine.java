package org.lili.security;

import com.google.common.base.Preconditions;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * @author lili
 * @date 2020/4/21 16:56
 * @description RSA生成公私钥，加密和解密，每个加解密机是单例的,后期优化：项目启动时候就创建好这些类
 * 这个类影响性能，需要仔细设计，静态工厂？BigInteger？
 */
public final class RSAEngine {

    private static final String CHARSET = "UTF-8";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_ALGORITHM_SIGN = "SHA256WithRSA";

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    /**
     * 公钥和私钥对
     */
    @Getter
    @Builder
    @Data
    public static class PubPriPair {
        private String publicKey;
        private String privateKey;
    }

    /**
     * 通过公钥解密
     *
     * @param publicKey     公钥
     * @param encryptedData 加密数据
     * @return
     */
    public static String decryptByPubKey(String encryptedData, String publicKey) {
        if (StringUtils.isBlank(encryptedData) || StringUtils.isBlank(publicKey)) {
            throw new IllegalArgumentException("can not be empty");
        }
        try {
            Base64 decoder = new Base64(true);
            byte[] data = decryptByPublicKey(decoder.decode(encryptedData), publicKey);
            if (data == null || data.length < 1) {
                return "";
            }
            return new String(data);
        } catch (Exception e) {
        }
        return "";
    }

    private static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }


    /** */
    /**
     * 加密算法RSA
     */
    private static final String KEY_ALGORITHM = "RSA";

    /** */
    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 234;

    /** */
    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 256;


    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }



    public static RSAEngine newDefaultEngine() {

        String publicKey = "encryptor_key_public";
        String privateKey = "encryptor_key_private";
        try {
            privateKey = AesUtils.decrypt(privateKey, System.getProperty("SystemParamConstants.KEY_PWD"));
        } catch (Exception e) {
            System.out.println("decrypt privateKey error,walletConfig:");
        }
        return new RSAEngine(publicKey, privateKey);
    }

    public static RSAEngine newEngine(String publicKey, String privateKey) {
        return new RSAEngine(publicKey, privateKey);
    }


    private RSAEngine(String publicKey, String privateKey) {
        Preconditions.checkArgument(StringUtils.isNotEmpty(publicKey), "publicKey can not be empty");
        Preconditions.checkArgument(StringUtils.isNotEmpty(privateKey), "privateKey can not be empty");
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            // 通过X509编码的Key指令获得公钥对象
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey.getBytes()));
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
            // 通过PKCS#8编码的Key指令获得私钥对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey.getBytes()));
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        } catch (Exception e) {
            throw new RuntimeException("unsupport key", e);
        }
    }

    public static PubPriPair createKeys(int keySize) {
        Preconditions.checkArgument(keySize > 0, "key size must be positive:" + keySize);
        Preconditions.checkArgument(keySize > 512, "key size must be large than 512:" + keySize);
        // 为RSA算法创建n个KeyPairGenerator对象
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm -> [" + RSA_ALGORITHM + "]");
        }
        // 初始化KeyPairGenerator对象,不要被initialize()源码表面上欺,其实这里声明的size是生效的
        kpg.initialize(keySize);
        // 生成秘钥
        KeyPair keyPair = kpg.generateKeyPair();
        // 得到公钥
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = new String(Base64.encodeBase64(publicKey.getEncoded()));
        // 得到私钥
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = new String(Base64.encodeBase64(privateKey.getEncoded()));
//        return PubPriPair.builder().privateKey(privateKeyStr).publicKey(publicKeyStr).build();
        return null;
    }

    // 公钥加密
    public String publicEncrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return new String(Base64.encodeBase64(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET),
                    publicKey.getModulus().bitLength())));
        } catch (Exception e) {
            throw new RuntimeException("公钥加密字符串[" + data + "]时遇到异常", e);
        }
    }

    // 私钥解密
    public String privateDecrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data.getBytes()),
                    publicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("私钥解密字符串[" + data + "]时遇到异常", e);
        }
    }

    // 私钥加密
    public String privateEncrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return new String(Base64.encodeBase64(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET),
                    publicKey.getModulus().bitLength())));
        } catch (Exception e) {
            throw new RuntimeException("私钥加密字符串[" + data + "]时遇到异常", e);
        }
    }

    // 公钥解密
    public String publicDecrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data.getBytes()),
                    publicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("公钥解密字符串[" + data + "]时遇到异常", e);
        }
    }

    // 私钥签名
    public String sign(String data) {
        try {
            Signature signature = Signature.getInstance(RSA_ALGORITHM_SIGN);
            signature.initSign(privateKey);
            signature.update(data.getBytes(CHARSET));
            return new String(Base64.encodeBase64(signature.sign()));
        } catch (Exception e) {
            throw new RuntimeException("私钥签名字符串[" + data + "]时遇到异常", e);
        }
    }

    // 公钥验签
    public boolean verify(String data, String sign) {
        try {
            Signature signature = Signature.getInstance(RSA_ALGORITHM_SIGN);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(CHARSET));
            return signature.verify(Base64.decodeBase64(sign.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("公钥验签字符串[" + data + "]时遇到异常", e);
        }
    }


    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
        int maxBlock = 0;
        if (opmode == Cipher.DECRYPT_MODE) {
            maxBlock = keySize / 8;
        } else {
            maxBlock = keySize / 8 - 11;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try {
            while (datas.length > offSet) {
                if (datas.length - offSet > maxBlock) {
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        } catch (Exception e) {
            throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
        }
        byte[] resultDatas = out.toByteArray();
        IOUtils.closeQuietly(out);
        return resultDatas;
    }
}
