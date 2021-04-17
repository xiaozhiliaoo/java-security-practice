package org.lili.security;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author lili
 * @date 2020/9/22 23:54
 * @see
 * @since
 */
public class RSAEngineTest {

    @Test
    public void createPublicPrivateKeys() {
        RSAEngine.PubPriPair keyPair = RSAEngine.createKeys(2048);
        String base = "hi-do-it";
        RSAEngine xRsa = RSAEngine.newEngine(keyPair.getPublicKey(), keyPair.getPrivateKey());
        assertEquals("私钥加密-公钥解密", base, xRsa.publicDecrypt(xRsa.privateEncrypt(base)));
        assertEquals("公钥加密-私钥解密", base, xRsa.privateDecrypt(xRsa.publicEncrypt(base)));
    }

    //公钥加密 相同内容每次密文都不一样 私钥加密每次都一样
    @Test
    public void privateEncrypt() {
        RSAEngine.PubPriPair keyPair = RSAEngine.createKeys(2048);
        String base = "hi-do-it";
        RSAEngine xRsa = RSAEngine.newEngine(keyPair.getPublicKey(), keyPair.getPrivateKey());
        String data = xRsa.privateEncrypt(base);
        String data2 = xRsa.privateEncrypt(base);
        String data3 = xRsa.privateEncrypt(base);
        assertEquals(data, data2);
        assertEquals(data, data3);
        assertEquals(data2, data3);
    }

    @Test
    public void publicEncrypt() {
        RSAEngine.PubPriPair keyPair = RSAEngine.createKeys(2048);
        String base = "hi-do-it";
        RSAEngine xRsa = RSAEngine.newEngine(keyPair.getPublicKey(), keyPair.getPrivateKey());
        String data = xRsa.publicEncrypt(base);
        String data2 = xRsa.publicEncrypt(base);
        String data3 = xRsa.publicEncrypt(base);
        assertNotEquals(data, data2);
        assertNotEquals(data, data3);
        assertNotEquals(data2, data3);
    }


    /**
     * 通信双方只有一对公私钥时候。
     */
    @Test
    public void onePublicPrivateKeyConnect() {
        RSAEngine.PubPriPair keyPair = RSAEngine.createKeys(2048);
        String base = "hi-do-it";
        RSAEngine xRsa = RSAEngine.newEngine(keyPair.getPublicKey(), keyPair.getPrivateKey());
        assertEquals("发送方私钥加密-接收方公钥解密", base, xRsa.publicDecrypt(xRsa.privateEncrypt(base)));
        assertEquals("接收方公钥加密-发送方私钥解密", base, xRsa.privateDecrypt(xRsa.publicEncrypt(base)));
    }

}