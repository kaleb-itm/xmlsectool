/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.tool.xmlsectool;

import java.util.List;

import javax.annotation.Nonnull;
import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Classes to assist with signature operations.
 */
public final class SignatureHelper {

    /** Elements which should be examined for CRs, and stripped of them. */
    private static final List<String> STRIP_CR_ELEMENTS = List.of(
            // Generic signatures
            "SignatureValue", "X509Certificate",
            // RSAKeyValue
            "Modulus",
            // DSAKeyValue
            "P", "Q", "G", "Y", "J"
        );

    /** Elements which should be forced into a NL - value - NL format. */
    private static final List<String> ENSURE_NL_ELEMENTS = List.of(
            // RSAKeyValue
            "Modulus",
            // DSAKeyValue
            "P", "G", "Y"
        );

    /**
     * Constructor.
     */
    private SignatureHelper() {
    }

    /**
     * Remove any CRs from the text content of named child elements.
     *
     * @param signature The <code>Signature</code> element to process.
     * @param elementName The element name within the XML DSIG namespace to look for.
     */
    private static void removeCRsFromNamedChildren(@Nonnull final Element signature,
            @Nonnull final String elementName) {
        final NodeList nodes = signature.getElementsByTagNameNS(XMLSignature.XMLNS, elementName);
        for (int i = 0; i < nodes.getLength(); i++) {
            final Node node = nodes.item(i);
            final String text = node.getTextContent();
            if (text.indexOf('\r') >= 0) {
                node.setTextContent(text.replaceAll("\\r", ""));
            }
        }
    }

    /**
     * Ensure a named child element is in a NL - value - NL format.
     *
     * @param signature The <code>Signature</code> element to process.
     * @param elementName The element name within the XML DSIG namespace to look for.
     */
    private static void ensureNLsWrapNamedChildren(@Nonnull final Element signature,
            @Nonnull final String elementName) {
        final NodeList nodes = signature.getElementsByTagNameNS(XMLSignature.XMLNS, elementName);
        for (int i = 0; i < nodes.getLength(); i++) {
            final Node node = nodes.item(i);
            final String text = node.getTextContent();
            final String newText = "\n" + text.strip() + "\n";
            if (!newText.equals(text)) {
                node.setTextContent(newText);
            }
        }
    }

    /**
     * Post-process a generated signature.
     *
     * @param signatureElement DOM {@link Element} containing the signature
     */
    public static void postProcessSignature(@Nonnull final Element signatureElement) {
        for (final var name : STRIP_CR_ELEMENTS) {
            removeCRsFromNamedChildren(signatureElement, name);
        }

        for (final var name : ENSURE_NL_ELEMENTS) {
            ensureNLsWrapNamedChildren(signatureElement, name);
        }
    }

}
