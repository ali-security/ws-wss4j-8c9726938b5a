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
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecDKSign;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

/**
 * CVE-2026-85532: the wsc:Length of a DerivedKeyToken is sender-controlled, so the
 * processor must reject derived keys shorter than 16 or longer than 512 bytes.
 */
public class TestWSSecurityDerivedKeyLength extends TestCase implements CallbackHandler {
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

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance("wss40.properties");
    private MessageContext msgContext;

    public TestWSSecurityDerivedKeyLength(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestWSSecurityDerivedKeyLength.class);
    }

    protected void setUp() throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
    }

    public void testDefaultLengthSignatureVerifies() throws Exception {
        assertSignatureVerifies(buildSignedDoc(-1));
    }

    public void testMinimumLengthSignatureVerifies() throws Exception {
        assertSignatureVerifies(buildSignedDoc(16));
    }

    public void testMaximumLengthSignatureVerifies() throws Exception {
        assertSignatureVerifies(buildSignedDoc(512));
    }

    public void testOneByteDerivedKeyIsRejected() throws Exception {
        assertRejected(buildSignedDoc(1));
    }

    public void testTooShortDerivedKeyIsRejected() throws Exception {
        assertRejected(buildSignedDoc(15));
    }

    public void testTooLongDerivedKeyIsRejected() throws Exception {
        assertRejected(buildSignedDoc(513));
    }

    public void testHugeDerivedKeyIsRejected() throws Exception {
        assertRejected(buildSignedDoc(64 * 1024));
    }

    private Document buildSignedDoc(int derivedKeyLength) throws Exception {
        InputStream in = new ByteArrayInputStream(SOAPMSG.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        Document doc = msg.getSOAPEnvelope().getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(doc, crypto);

        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(encrKeyBuilder.getEphemeralKey(), encrKeyBuilder.getId());
        sigBuilder.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        if (derivedKeyLength > 0) {
            sigBuilder.setDerivedKeyLength(derivedKeyLength);
        }
        sigBuilder.build(doc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);
        return doc;
    }

    private void assertSignatureVerifies(Document doc) throws Exception {
        Vector results = secEngine.processSecurityHeader(doc, null, this, crypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult);
    }

    private void assertRejected(Document doc) throws Exception {
        try {
            secEngine.processSecurityHeader(doc, null, this, crypto);
            fail("A derived key length outside [16, 512] bytes must be rejected");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.INVALID_SECURITY, ex.getErrorCode());
        }
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
