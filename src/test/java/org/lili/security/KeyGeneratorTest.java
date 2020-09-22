package org.lili.security;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * @author lili
 * @date 2020/9/23 1:22
 * @see
 * @since
 */
public class KeyGeneratorTest {
    @Test
    public void test() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey secretKey = kg.generateKey();
        byte[] encoded = secretKey.getEncoded();
    }
}
