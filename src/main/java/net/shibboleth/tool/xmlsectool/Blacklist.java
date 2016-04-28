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

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

import org.opensaml.xml.signature.SignatureConstants;

/**
 * A blacklist of digest and signature algorithms we should not accept during
 * signature verification.
 */
public class Blacklist {
    
    /**
     * Ordered set of blacklisted digest algorithm URIs.
     */
    private final Set<String> digestBlacklist = new TreeSet<String>();
    
    /**
     * Ordered set of blacklisted signature algorithm URIs.
     */
    private final Set<String> signatureBlacklist = new TreeSet<String>();
    
    /**
     * Constructor.
     *
     * Initializes the blacklist with those algorithms that should be
     * blacklisted by default.
     */
    public Blacklist() {
        // MD5
        addDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
        addSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5);
        
        // SHA-1
        addDigest(DigestChoice.SHA1);
    }
    
    /**
     * Blacklist an individual digest algorithm.
     * 
     * @param uri algorithm URI to blacklist
     */
    private void addDigestAlgorithm(String uri) {
        digestBlacklist.add(uri);
    }
    
    /**
     * Blacklist an individual signature algorithm.
     * 
     * @param uri algorithm URI to blacklist
     */
    private void addSignatureAlgorithm(String uri) {
        signatureBlacklist.add(uri);
    }
    
    /**
     * Blacklist the digest and signature algorithms associated with
     * a {@link DigestChoice}.
     * 
     * @param digestChoice {@link DigestChoice} to add to blacklist
     */
    public void addDigest(DigestChoice digestChoice) {
        addDigestAlgorithm(digestChoice.getDigestAlgorithm());
        addSignatureAlgorithm(digestChoice.getRsaAlgorithm());
        addSignatureAlgorithm(digestChoice.getEcdsaAlgorithm());
    }
    
    /**
     * Returns <code>true</code> if the indicated algorithm URI is blacklisted for
     * use as a digest algorithm.
     * 
     * @param alg digest algorithm URI to check
     * @return <code>true</code> if the algorithm is blacklisted
     */
    public boolean isBlacklistedDigest(String alg) {
        return digestBlacklist.contains(alg);
    }
    
    /**
     * Returns <code>true</code> if the indicated algorithm URI is blacklisted for
     * use as a signature algorithm.
     * 
     * @param alg signature algorithm URI to check
     * @return <code>true</code> if the algorithm is blacklisted
     */
    public boolean isBlacklistedSignature(String alg) {
        return signatureBlacklist.contains(alg);
    }
    
    /**
     * Returns an unmodifiable view on the set of blacklisted digest algorithms.
     * 
     * @return set of blacklisted algorithms
     */
    public Collection<String> getDigestBlacklist() {
        return Collections.unmodifiableCollection(digestBlacklist);
    }
    
    /**
     * Returns an unmodifiable view on the set of blacklisted signature algorithms.
     * 
     * @return set of blacklisted algorithms
     */
    public Collection<String> getSignatureBlacklist() {
        return Collections.unmodifiableCollection(signatureBlacklist);
    }
    
    /**
     * Empties the digest and signature blacklists.
     */
    public void clear() {
        digestBlacklist.clear();
        signatureBlacklist.clear();
    }
}
