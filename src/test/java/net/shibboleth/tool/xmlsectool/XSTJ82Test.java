package net.shibboleth.tool.xmlsectool;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

import javax.xml.transform.dom.DOMSource;

import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.ElementSupport;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder.SchemaLanguage;

/**
 * Test for <code>--pkcs11Config</code> option under Java 11+.
 * 
 * <p>
 * It's really hard to provide tests for this bean that will run anywhere, because
 * by definition it requires access to a PKCS#11 token, which is not something you'll
 * find on any street corner.
 * </p>
 * 
 * <p>
 * The approach taken here is to have a number of (by default <em>disabled</em> tests
 * exercising specific scenarios with specific tokens.
 * </p>
 */
public class XSTJ82Test extends BaseTest {

    XSTJ82Test() {
        super(XSTJ82Test.class);
    }

    @Test(enabled = false)
    public void xstj82() throws Exception {
        // Locate the PKCS#11 configuration file
        final var configFile = packageRelativeFile("softhsm.cfg");

        // build command-line arguments
        final String[] args = {
                "--sign",
                "--inFile", "in.xml",
                "--outFile", "out.xml",
                "--pkcs11Config", configFile.getAbsolutePath(),
                "--keystoreProvider", "dummy",
                "--keyPassword", "1234",
                "--key", "key2048",
                };
        final CommandLineArguments cli = new CommandLineArguments();
        cli.parseCommandLineArguments(args);
        XMLSecTool.initLogging(cli);

        // Deep unit test on the CredentialHelper's credential acquisition method
        var cred = CredentialHelper.getPKCS11Credential(cli.getKeystoreProvider(), cli.getPkcs11Config(),
                cli.getKey(), cli.getKeyPassword());
        Assert.assertNotNull(cred);

        var pubKey = cred.getPublicKey();
        Assert.assertNotNull(pubKey);
        Assert.assertEquals(pubKey.getAlgorithm(), "RSA");
        Assert.assertTrue(pubKey instanceof RSAPublicKey);
        var rsaPubKey = (RSAPublicKey) pubKey;
        Assert.assertEquals(rsaPubKey.getModulus().bitLength(), 2048);

        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XMLSecTool.sign(cli, cred, xml);
        
        // verify the signature using our own code for consistency
        XMLSecTool.verifySignature(cli, cred, xml);

        // take a careful look at the signature
        final Element signatureElement = XMLSecTool.getSignatureElement(xml);
        final Element keyInfoElement = ElementSupport.getFirstChildElement(signatureElement,
                KeyInfo.DEFAULT_ELEMENT_NAME);
        final List<Element> keyInfoChildren = ElementSupport.getChildElements(keyInfoElement);
        Assert.assertFalse(keyInfoChildren.isEmpty());
        final List<Element> keyValues = ElementSupport.getChildElements(keyInfoElement, KeyValue.DEFAULT_ELEMENT_NAME);
        for (final Element keyValue : keyValues) {
            Assert.assertNotNull(ElementSupport.getFirstChildElement(keyValue), "empty KeyValue element");
        }

        // validate the resulting XML; this will also show up any error
        final SchemaValidator validator = new SchemaValidator(SchemaLanguage.XML, getSchemaDirectory());
        validator.validate(new DOMSource(xml));
    }
}
