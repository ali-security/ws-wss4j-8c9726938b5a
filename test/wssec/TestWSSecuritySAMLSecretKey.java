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
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecDKSign;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Vector;

/**
 * CVE-2026-88920: a wst:BinarySecret in a SAML assertion's Subject KeyInfo must not be
 * accepted as a signing key unless the assertion is holder-of-key and signed by a trusted issuer.
 */
public class TestWSSecuritySAMLSecretKey extends TestCase implements CallbackHandler {
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

    private static final String ASSERTION_ID = "_attacker-assertion-1";
    private static final byte[] ATTACKER_SECRET = "attacker-controlled-shared-secret".getBytes();

    private static final String TRUSTED_ALIAS = "wss40";
    private static final String UNTRUSTED_ALIAS = "16c73ab6-b892-458f-abf5-2f875f74882e";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance("wss40.properties");
    private Crypto untrustedCrypto = CryptoFactory.getInstance("crypto.properties");
    private MessageContext msgContext;

    public TestWSSecuritySAMLSecretKey(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestWSSecuritySAMLSecretKey.class);
    }

    protected void setUp() throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
    }

    public void testSenderVouchesSecretKeyIdentifierIsRejected() throws Exception {
        Element assertion = createAssertion(SAMLSubject.CONF_SENDER_VOUCHES);
        assertRejected(buildSignedDoc(assertion, WSConstants.CUSTOM_KEY_IDENTIFIER));
    }

    public void testSenderVouchesSecretKeyDirectReferenceIsRejected() throws Exception {
        Element assertion = createAssertion(SAMLSubject.CONF_SENDER_VOUCHES);
        assertRejected(buildSignedDoc(assertion, WSConstants.CUSTOM_SYMM_SIGNING));
    }

    public void testUnsignedHolderOfKeySecretKeyIsRejected() throws Exception {
        Element assertion = createAssertion(SAMLSubject.CONF_HOLDER_KEY);
        assertRejected(buildSignedDoc(assertion, WSConstants.CUSTOM_KEY_IDENTIFIER));
    }

    public void testUntrustedSignedHolderOfKeySecretKeyIsRejected() throws Exception {
        Element assertion = signAssertion(
            createAssertion(SAMLSubject.CONF_HOLDER_KEY), untrustedCrypto, UNTRUSTED_ALIAS
        );
        Document doc = buildSignedDoc(assertion, WSConstants.CUSTOM_KEY_IDENTIFIER);
        try {
            secEngine.processSecurityHeader(doc, null, this, crypto);
            fail("A SAML assertion signed by an untrusted issuer must not supply a secret key");
        } catch (WSSecurityException ex) {
            // Merlin.validateCertPath throws FAILURE "certpath" for an untrusted issuer
        }
    }

    public void testTrustedSignedHolderOfKeySecretKeyVerifies() throws Exception {
        Element assertion = signAssertion(
            createAssertion(SAMLSubject.CONF_HOLDER_KEY), crypto, TRUSTED_ALIAS
        );
        Document doc = reparse(buildSignedDoc(assertion, WSConstants.CUSTOM_KEY_IDENTIFIER));
        Vector results = secEngine.processSecurityHeader(doc, null, this, crypto);
        assertNotNull(WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN));
    }

    public void testUnsignedHolderOfKeyDerivedKeySecretIsRejected() throws Exception {
        Document doc = newDoc();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(ATTACKER_SECRET, ASSERTION_ID);
        sigBuilder.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        sigBuilder.build(doc, secHeader);

        prependToSecurityHeader(
            secHeader, doc, createAssertion(SAMLSubject.CONF_HOLDER_KEY)
        );
        assertRejected(doc);
    }

    /**
     * HMAC-signs the Body with ATTACKER_SECRET, referencing the given SAML assertion.
     */
    private Document buildSignedDoc(Element assertion, int keyIdentifierType)
        throws Exception {
        Document doc = newDoc();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecSignature sign = new WSSecSignature();
        sign.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        sign.setKeyIdentifierType(keyIdentifierType);
        sign.setSecretKey(ATTACKER_SECRET);
        sign.setCustomTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
        sign.setCustomTokenId(ASSERTION_ID);
        sign.build(doc, crypto, secHeader);

        prependToSecurityHeader(secHeader, doc, assertion);
        return doc;
    }

    /**
     * Serializes and parses the message again, as a receiver would see it.
     */
    private static Document reparse(Document doc) throws Exception {
        String xml = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }

    private Document newDoc() throws Exception {
        InputStream in = new ByteArrayInputStream(SOAPMSG.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg.getSOAPEnvelope().getAsDocument();
    }

    private static void prependToSecurityHeader(
        WSSecHeader secHeader, Document doc, Element assertion
    ) {
        Element securityHeader = secHeader.getSecurityHeader();
        securityHeader.insertBefore(doc.importNode(assertion, true), securityHeader.getFirstChild());
    }

    private static Element signAssertion(Element assertionElement, Crypto issuerCrypto, String alias)
        throws Exception {
        SAMLAssertion assertion = new SAMLAssertion(assertionElement);
        X509Certificate[] certs = issuerCrypto.getCertificates(alias);
        Key key = issuerCrypto.getPrivateKey(alias, "security");
        assertion.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA, key, Arrays.asList(certs));
        return (Element) assertion.toDOM();
    }

    private static Element createAssertion(String confirmationMethod) throws Exception {
        String xml = 
            "<saml:Assertion xmlns:saml=\"" + WSConstants.SAML_NS + "\" MajorVersion=\"1\" "
            +   "MinorVersion=\"1\" AssertionID=\"" + ASSERTION_ID + "\" "
            +   "Issuer=\"attacker.example.com\" IssueInstant=\"2010-09-28T12:00:00.000Z\">"
            +   "<saml:AttributeStatement>"
            +     "<saml:Subject>"
            +       "<saml:NameIdentifier>attacker</saml:NameIdentifier>"
            +       "<saml:SubjectConfirmation>"
            +         "<saml:ConfirmationMethod>" + confirmationMethod + "</saml:ConfirmationMethod>"
            +         "<ds:KeyInfo xmlns:ds=\"" + WSConstants.SIG_NS + "\">"
            +           "<wst:BinarySecret xmlns:wst=\"" + WSConstants.WST_NS + "\">"
            +             Base64.encode(ATTACKER_SECRET)
            +           "</wst:BinarySecret>"
            +         "</ds:KeyInfo>"
            +       "</saml:SubjectConfirmation>"
            +     "</saml:Subject>"
            +     "<saml:Attribute AttributeName=\"role\" AttributeNamespace=\"urn:test\">"
            +       "<saml:AttributeValue>admin</saml:AttributeValue>"
            +     "</saml:Attribute>"
            +   "</saml:AttributeStatement>"
            + "</saml:Assertion>";
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder()
            .parse(new ByteArrayInputStream(xml.getBytes("UTF-8"))).getDocumentElement();
    }

    private void assertRejected(Document doc) throws Exception {
        try {
            secEngine.processSecurityHeader(doc, null, this, crypto);
            fail("A secret key from an untrusted or non-holder-of-key SAML assertion must be rejected");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.FAILED_CHECK, ex.getErrorCode());
        }
    }

    /**
     * Supplies no key for the SAML CUSTOM_TOKEN lookup, so the key comes from the assertion.
     */
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
    }
}
