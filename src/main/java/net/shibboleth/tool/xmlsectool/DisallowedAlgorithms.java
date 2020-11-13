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

import java.io.PrintStream;
import java.util.Set;
import java.util.TreeSet;

import org.opensaml.xmlsec.signature.support.SignatureConstants;

/**
 * A collection of insecure or otherwise undesirable digest algorithms and signature algorithms,
 * to be used to prevent their use in the validation of digital signatures.
 */
public class DisallowedAlgorithms {
    
    /**
     * Ordered set of disallowed digest algorithm URIs.
     */
    private final Set<String> digestAlgorithms = new TreeSet<>();
    
    /**
     * Ordered set of disallowed signature algorithm URIs.
     */
    private final Set<String> signatureAlgorithms = new TreeSet<>();
    
    /**
     * Constructor.
     *
     * Initializes the collections with those algorithms that should be
     * regarded as unusable by default.
     */
    public DisallowedAlgorithms() {
        // MD5
        digestAlgorithms.add(SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
        signatureAlgorithms.add(SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5);
        
        // SHA-1
        disallowDigest(DigestChoice.SHA1);
    }
    
    /**
     * Add the digest and signature algorithms associated with
     * a {@link DigestChoice}.
     * 
     * @param digestChoice {@link DigestChoice} to add
     */
    public void disallowDigest(final DigestChoice digestChoice) {
        digestAlgorithms.add(digestChoice.getDigestAlgorithm());
        signatureAlgorithms.add(digestChoice.getRSAAlgorithm());
        signatureAlgorithms.add(digestChoice.getECDSAAlgorithm());
    }
    
    /**
     * Remove the digest and signature algorithms associated with
     * a {@link DigestChoice}.
     * 
     * @param digestChoice {@link DigestChoice} to remove
     */
    public void allowDigest(final DigestChoice digestChoice) {
        digestAlgorithms.remove(digestChoice.getDigestAlgorithm());
        signatureAlgorithms.remove(digestChoice.getRSAAlgorithm());
        signatureAlgorithms.remove(digestChoice.getECDSAAlgorithm());
    }
    
    /**
     * Returns <code>true</code> if the indicated algorithm URI is disallowed for
     * use as a digest algorithm.
     * 
     * @param alg digest algorithm URI to check
     * @return <code>true</code> if the algorithm is disallowed
     */
    public boolean isDigestAlgorithmDisallowed(final String alg) {
        return digestAlgorithms.contains(alg);
    }

    /**
     * Returns <code>true</code> if the indicated algorithm URI is disallowed for
     * use as a signature algorithm.
     * 
     * @param alg signature algorithm URI to check
     * @return <code>true</code> if the algorithm is disallowed
     */
    public boolean isSignatureAlgorithmDisallowed(final String alg) {
        return signatureAlgorithms.contains(alg);
    }
    
    /**
     * Empties the disallowed digest and signature algorithm lists.
     */
    public void allowAllDigests() {
        digestAlgorithms.clear();
        signatureAlgorithms.clear();
    }
    
    /**
     * List out the contents of the algorithm collections.
     * 
     * @param out stream to send the listing to
     */
    public void list(final PrintStream out) {
        out.println("Disallowed digest algorithms:");
        if (digestAlgorithms.isEmpty()) {
            out.println("   (none)");
        } else {
            for (final String uri: digestAlgorithms) {
                out.println("   " + uri);
            }
        }
        out.println();
        out.println("Disallowed signature algorithms:");
        if (signatureAlgorithms.isEmpty()) {
            out.println("   (none)");
        } else {
            for (final String uri : signatureAlgorithms) {
                out.println("   " + uri);
            }
        }
        out.println();
    }
}
