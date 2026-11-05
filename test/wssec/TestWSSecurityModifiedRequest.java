/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * WS-Security Test Case for modified (attacker controlled) EncryptedKey structures.
 * <p/>
 * An attacker that can submit a modified xenc:EncryptedKey (RSA PKCS#1 v1.5 key
 * transport) must not be able to tell from the response whether the modified
 * CipherValue decrypted to a PKCS#1 conforming plaintext of a usable key length or not
 * (Bleichenbacher attack, CVE-2011-2487). Any such failure must look exactly like a
 * failure to decrypt the EncryptedData with a wrong session key.
 */
public class TestWSSecurityModifiedRequest extends TestCase implements CallbackHandler {
    private static final String SOAPMSG =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        +   "<SOAP-ENV:Body>"
        +      "<ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>"
        +   "</SOAP-ENV:Body>"
        + "</SOAP-ENV:Envelope>";

    private Crypto crypto = CryptoFactory.getInstance("wss40.properties");
    private SecureRandom random = new SecureRandom();
    private MessageContext msgContext;

    /**
     * TestWSSecurity constructor
     * <p/>
     *
     * @param name name of the test
     */
    public TestWSSecurityModifiedRequest(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     *
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityModifiedRequest.class);
    }

    /**
     * Setup method
     * <p/>
     *
     * @throws Exception Thrown when there is a problem in setup
     */
    protected void setUp() throws Exception {
        // make sure xmlsec (JCEMapper) and the JCE providers are initialized
        WSSConfig.getDefaultWSConfig();
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
    }

    /**
     * Test that an EncryptedKey whose CipherValue does not decrypt to a PKCS#1 v1.5
     * conforming block fails exactly like an EncryptedKey that contains a (conforming)
     * wrong session key, i.e. the padding check can't be used as an oracle.
     */
    public void testBadPaddingEncryptedKey() throws Exception {
        RSAPublicKey publicKey = getRecipientKey();
        int k = getModulusLength(publicKey);
        //
        // 0x00 || 0x03 || PS || 0x00 || key - an unknown block type, this is not
        // PKCS#1 v1.5 conforming for any RSA implementation
        //
        byte[] block = new byte[k];
        block[0] = 0x00;
        block[1] = 0x03;
        for (int i = 2; i < k - 17; i++) {
            block[i] = (byte) 0xFF;
        }
        block[k - 17] = 0x00;
        byte[] key = new byte[16];
        random.nextBytes(key);
        System.arraycopy(key, 0, block, k - 16, 16);

        Throwable expected = processWithCipherValue(rsaEncryptWrongKey(16));
        Throwable actual = processWithCipherValue(rsaRawEncrypt(publicKey, block));
        assertSameFailure(expected, actual);
    }

    /**
     * Test that an EncryptedKey whose CipherValue is longer than the RSA modulus fails
     * exactly like an EncryptedKey that contains a (conforming) wrong session key.
     */
    public void testOversizedEncryptedKey() throws Exception {
        byte[] cipherValue = new byte[2 * getModulusLength(getRecipientKey())];
        random.nextBytes(cipherValue);

        Throwable expected = processWithCipherValue(rsaEncryptWrongKey(16));
        Throwable actual = processWithCipherValue(cipherValue);
        assertSameFailure(expected, actual);
    }

    /**
     * Test that a PKCS#1 v1.5 conforming EncryptedKey that holds a key which is too short
     * for the symmetric algorithm fails exactly like one that holds a wrong session key.
     */
    public void testShortDecryptedKey() throws Exception {
        Throwable expected = processWithCipherValue(rsaEncryptWrongKey(16));
        Throwable actual = processWithCipherValue(rsaEncryptWrongKey(5));
        assertSameFailure(expected, actual);
    }

    /**
     * Test that a PKCS#1 v1.5 conforming EncryptedKey that holds a key which is too long
     * for the symmetric algorithm fails exactly like one that holds a wrong session key.
     */
    public void testOverlongDecryptedKey() throws Exception {
        Throwable expected = processWithCipherValue(rsaEncryptWrongKey(16));
        Throwable actual = processWithCipherValue(rsaEncryptWrongKey(20));
        assertSameFailure(expected, actual);
    }

    /**
     * Test that the decrypted session key is cut to the key length required by the
     * symmetric encryption algorithm (AES-128 here).
     */
    public void testOverlongDecryptedKeyIsTruncated() throws Exception {
        Document doc = getSOAPDocument();
        WSSecEncrypt builder = encrypt(doc);
        byte[] sessionKey = builder.getSymmetricKey().getEncoded();
        assertEquals(16, sessionKey.length);

        byte[] overlongKey = new byte[32];
        random.nextBytes(overlongKey);
        System.arraycopy(sessionKey, 0, overlongKey, 0, sessionKey.length);
        setCipherValue(builder, rsaEncrypt(overlongKey));

        new WSSecurityEngine().processSecurityHeader(doc, null, this, crypto);
        String outputString =
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("LogTestService2") > 0);
    }

    /**
     * Test the key length check of WSSecurityUtil.prepareSecretKey()
     */
    public void testPrepareSecretKeyLength() throws Exception {
        byte[] rawKey = new byte[40];
        random.nextBytes(rawKey);

        SecretKey key = WSSecurityUtil.prepareSecretKey(WSConstants.AES_128, rawKey);
        assertEquals(16, key.getEncoded().length);
        assertEquals("AES", key.getAlgorithm());
        key = WSSecurityUtil.prepareSecretKey(WSConstants.AES_192, rawKey);
        assertEquals(24, key.getEncoded().length);
        key = WSSecurityUtil.prepareSecretKey(WSConstants.AES_256, rawKey);
        assertEquals(32, key.getEncoded().length);
        key = WSSecurityUtil.prepareSecretKey(WSConstants.TRIPLE_DES, rawKey);
        assertEquals(24, key.getEncoded().length);

        byte[] shortKey = new byte[8];
        random.nextBytes(shortKey);
        key = WSSecurityUtil.prepareSecretKey(WSConstants.AES_256, shortKey);
        assertEquals(8, key.getEncoded().length);
    }

    /**
     * Test that the message of a WSSecurityException does not include the message
     * of the underlying (e.g. padding) exception.
     */
    public void testExceptionMessageDoesNotLeakCause() throws Exception {
        BadPaddingException cause = new BadPaddingException("Decryption error");
        WSSecurityException ex =
            new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, cause);
        assertEquals("The signature or decryption was invalid", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertTrue(ex.getMessage(true).indexOf("Decryption error") != -1);
        assertEquals(ex.getMessage(), ex.getMessage(false));

        ex = new WSSecurityException("Some error", cause);
        assertEquals("Some error", ex.getMessage());
        assertSame(cause, ex.getCause());

        ex = new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null);
        assertEquals("The signature or decryption was invalid", ex.getMessage());
        assertNull(ex.getCause());
    }

    /**
     * Test that changing the symmetric encryption algorithm discards a symmetric key
     * created for another algorithm.
     */
    public void testChangingSymmetricAlgorithm() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setSymmetricKey(key);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        assertSame(key, builder.getSymmetricKey());
        builder.setSymmetricEncAlgorithm(WSConstants.AES_256);
        assertNull(builder.getSymmetricKey());
    }

    /**
     * Check that the processing of the modified message failed in the same way as
     * the processing of the message with a wrong session key.
     */
    private static void assertSameFailure(Throwable expected, Throwable actual) {
        assertTrue(
            "Unexpected failure: " + expected, expected instanceof WSSecurityException
        );
        assertTrue("Unexpected failure: " + actual, actual instanceof WSSecurityException);
        WSSecurityException expectedEx = (WSSecurityException) expected;
        WSSecurityException actualEx = (WSSecurityException) actual;
        assertEquals(WSSecurityException.FAILED_CHECK, expectedEx.getErrorCode());
        assertEquals(expectedEx.getErrorCode(), actualEx.getErrorCode());
        assertEquals(expectedEx.getFaultCode(), actualEx.getFaultCode());
        assertEquals(expectedEx.getMessage(), actualEx.getMessage());
        assertFalse(
            "RSA padding failure exposed: " + actualEx.getCause(),
            actualEx.getCause() instanceof BadPaddingException
                || actualEx.getCause() instanceof IllegalBlockSizeException
        );
    }

    /**
     * Encrypt a fresh message, replace the CipherValue of the EncryptedKey and process
     * the message.
     *
     * @return the failure raised by the processing
     */
    private Throwable processWithCipherValue(byte[] cipherValue) throws Exception {
        Document doc = getSOAPDocument();
        WSSecEncrypt builder = encrypt(doc);
        setCipherValue(builder, cipherValue);
        try {
            new WSSecurityEngine().processSecurityHeader(doc, null, this, crypto);
        } catch (Throwable t) {
            return t;
        }
        fail("Failure expected on a modified EncryptedKey");
        return null;
    }

    private WSSecEncrypt encrypt(Document doc) throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setKeyEnc(WSConstants.KEYTRANSPORT_RSA15);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        builder.build(doc, crypto, secHeader);
        return builder;
    }

    private static void setCipherValue(WSSecEncrypt builder, byte[] value) {
        Element encryptedKey = builder.getEncryptedKeyElement();
        assertNotNull(encryptedKey);
        Element cipherData =
            WSSecurityUtil.getDirectChildElement(encryptedKey, "CipherData", WSConstants.ENC_NS);
        assertNotNull(cipherData);
        Element cipherValue =
            WSSecurityUtil.getDirectChildElement(cipherData, "CipherValue", WSConstants.ENC_NS);
        assertNotNull(cipherValue);
        while (cipherValue.getFirstChild() != null) {
            cipherValue.removeChild(cipherValue.getFirstChild());
        }
        cipherValue.appendChild(
            cipherValue.getOwnerDocument().createTextNode(Base64.encode(value))
        );
    }

    private Document getSOAPDocument() throws Exception {
        InputStream in = new ByteArrayInputStream(SOAPMSG.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg.getSOAPEnvelope().getAsDocument();
    }

    private RSAPublicKey getRecipientKey() throws Exception {
        X509Certificate[] certs = crypto.getCertificates("wss40");
        assertNotNull(certs);
        return (RSAPublicKey) certs[0].getPublicKey();
    }

    private static int getModulusLength(RSAPublicKey publicKey) {
        return (publicKey.getModulus().bitLength() + 7) / 8;
    }

    /**
     * PKCS#1 v1.5 encrypt a random key of the given length with the recipient's key
     */
    private byte[] rsaEncryptWrongKey(int keyLength) throws Exception {
        byte[] key = new byte[keyLength];
        random.nextBytes(key);
        return rsaEncrypt(key);
    }

    /**
     * PKCS#1 v1.5 encrypt the data with the recipient's key
     */
    private byte[] rsaEncrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getRecipientKey());
        return cipher.doFinal(data);
    }

    /**
     * Raw (textbook) RSA encryption of the given block with the recipient's key
     */
    private static byte[] rsaRawEncrypt(RSAPublicKey publicKey, byte[] block) {
        int k = getModulusLength(publicKey);
        BigInteger m = new BigInteger(1, block);
        BigInteger c = m.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        byte[] raw = c.toByteArray();
        byte[] result = new byte[k];
        if (raw.length > k) {
            System.arraycopy(raw, raw.length - k, result, 0, k);
        } else {
            System.arraycopy(raw, 0, result, k - raw.length, raw.length);
        }
        return result;
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                pc.setPassword("security");
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
