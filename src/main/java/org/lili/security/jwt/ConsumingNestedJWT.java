package org.lili.security.jwt;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author lili
 * @date 2020/9/25 0:22
 * @notes
 */
public class ConsumingNestedJWT {
    @Test
    public void test() throws Exception {
        //The recipient will first need to decrypt the JWE object,
        // then extract the signed JWT from its payload and verify the signature.
        // Parse the JWE string
//        JWEObject jweObject = JWEObject.parse("jweString");

        // Decrypt with private key
//        jweObject.decrypt(new RSADecrypter("recipientJWK"));

        // Extract payload
//        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

//        assertNotNull("Payload not a signed JWT", signedJWT);

        // Check the signature
//        assertTrue(signedJWT.verify(new RSASSAVerifier("senderPublicJWK")));

        // Retrieve the JWT claims...
//        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
    }
}
