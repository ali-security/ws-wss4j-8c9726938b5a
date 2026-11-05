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
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Vector;

/**
 * CVE-2026-89238: the header promoted out of a wsse11:EncryptedHeader must be the one that
 * was decrypted, not whatever unencrypted element an attacker places first in the wrapper.
 */
public class TestWSSecurityEncryptedHeaderChild extends TestCase implements CallbackHandler {
    private static final String SOAPMSG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<soapenv:Envelope xmlns:foo=\"urn:foo.bar\" "
        +   "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        +   "<soapenv:Header>"
        +     "<foo:foobar>baz</foo:foobar>"
        +   "</soapenv:Header>"
        +   "<soapenv:Body>"
        +     "<ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>"
        +   "</soapenv:Body>"
        + "</soapenv:Envelope>";

    private static final String ATTACKER_NS = "urn:attacker";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance("wss40.properties");
    private MessageContext msgContext;

    public TestWSSecurityEncryptedHeaderChild(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestWSSecurityEncryptedHeaderChild.class);
    }

    protected void setUp() throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
    }

    public void testEncryptedHeaderDecrypts() throws Exception {
        Document doc = buildEncryptedHeaderDoc();
        Vector results = secEngine.processSecurityHeader(doc, null, this, crypto);
        assertDecryptedHeaderPromoted(doc, results);
    }

    public void testUnencryptedFirstChildIsNotPromoted() throws Exception {
        Document doc = buildEncryptedHeaderDoc();
        Element encryptedHeader = getEncryptedHeader(doc);
        Element attackerHeader = doc.createElementNS(ATTACKER_NS, "attacker:header");
        attackerHeader.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:attacker", ATTACKER_NS);
        encryptedHeader.insertBefore(attackerHeader, encryptedHeader.getFirstChild());

        Vector results = secEngine.processSecurityHeader(doc, null, this, crypto);
        assertDecryptedHeaderPromoted(doc, results);
        assertEquals(0, doc.getElementsByTagNameNS(ATTACKER_NS, "header").getLength());
    }

    private Document buildEncryptedHeaderDoc() throws Exception {
        InputStream in = new ByteArrayInputStream(SOAPMSG.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        Document doc = msg.getSOAPEnvelope().getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("wss40");
        encrypt.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Vector parts = new Vector();
        parts.add(new WSEncryptionPart("foobar", "urn:foo.bar", "Header"));
        encrypt.setParts(parts);
        encrypt.build(doc, crypto, secHeader);

        assertNotNull(getEncryptedHeader(doc));
        assertEquals(0, doc.getElementsByTagNameNS("urn:foo.bar", "foobar").getLength());
        return doc;
    }

    private static Element getEncryptedHeader(Document doc) {
        return (Element) doc.getElementsByTagNameNS(
            WSConstants.WSSE11_NS, WSConstants.ENCRYPTED_HEADER).item(0);
    }

    private static void assertDecryptedHeaderPromoted(Document doc, Vector results) {
        assertEquals(0, doc.getElementsByTagNameNS(
            WSConstants.WSSE11_NS, WSConstants.ENCRYPTED_HEADER).getLength());
        Node promoted = doc.getElementsByTagNameNS("urn:foo.bar", "foobar").item(0);
        assertNotNull("the decrypted header must be promoted into the SOAP header", promoted);
        assertEquals("baz", promoted.getFirstChild().getNodeValue());

        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertNotNull(actionResult);
        List refs = (List) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertEquals(1, refs.size());
        assertSame(promoted, ((WSDataRef) refs.get(0)).getProtectedElement());
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
