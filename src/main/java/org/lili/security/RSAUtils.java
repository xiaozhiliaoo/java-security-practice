package org.lili.security;


import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author yufan
 */
public class RSAUtils {
    private static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void generatorKey() throws NoSuchAlgorithmException {
        // 获取生成密钥对对象
        KeyPairGenerator rsa = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        // 生成密钥
        rsa.initialize(1024, new SecureRandom());
        KeyPair keyPair = rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("公钥：" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("私钥：" + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
    }

    /**
     * 根据公钥加密 返回base64编码密文
     *
     * @param hash 加密原文
     * @return base64密文
     * @throws Exception 加密异常
     */
    public static String encryptByPub(String hash, String publicKey) throws Exception{
        PublicKey pub = KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] bytes = cipher.doFinal(hash.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytes);
    }


    /**
     * 根据公钥解密 解密base64编码密文
     *
     * @param encode base64密文
     * @return 解密后明文
     * @throws Exception 解密异常
     */
    public static String decryptByPub(String encode, String publicKey) throws Exception{
        PublicKey pub = KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, pub);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encode)));
    }


    /**
     * 根据私钥解密 解密base64编码密文
     *
     * @param encode base64密文
     * @return 解密后明文
     * @throws Exception 解密异常
     */
    public static String decryptByPrv(String encode, String privateKey) throws Exception{
        PrivateKey prv = KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, prv);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encode)));
    }

    /**
     * 根据私钥加密 返回base64编码密文
     *
     * @param hash 加密原文
     * @return base64密文
     * @throws Exception 加密异常
     */
    public static String encryptByPrv(String hash, String privateKey) throws Exception{
        PrivateKey prv = KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, prv);
        byte[] bytes = cipher.doFinal(hash.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytes);

    }

    /**
     * 签名
     * @param key         私钥
     * @param requestData 请求参数
     * @return
     */
    public static String sign(String key, String requestData) {
        String signature = null;
        byte[] signed = null;
        try {
            PrivateKey privateKey = getPrivateKey(key);

            Signature Sign = Signature.getInstance(SIGNATURE_ALGORITHM);
            Sign.initSign(privateKey);
            Sign.update(requestData.getBytes());
            signed = Sign.sign();

            signature = Base64.getEncoder().encodeToString(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return signature;
    }

    /**
     * 解码PrivateKey
     * @param key
     * @return
     */
    public static PrivateKey getPrivateKey(String key) {
        try {
            Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            byte[] byteKey = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(byteKey);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 解码publicKey
     * @param key
     * @return
     */
    public static PublicKey getPublicKey(String key){
        try {
//            byte[] keyBytes;
//            keyBytes = (new BASE64Decoder()).decodeBuffer(key);
//            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            byte[] certder = Base64.getDecoder().decode(key);
            InputStream certstream = new ByteArrayInputStream(certder);
            Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(certstream);
            PublicKey publicKey = cert.getPublicKey();
            return publicKey;
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥签名 -- Myinfo
     * @param baseString
     * @param privateKey
     * @return
     */
    public static String createSHA256withRSASignature(String baseString, PrivateKey privateKey) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(baseString.getBytes("UTF-8"));
            byte[] signature = rsa.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

}
