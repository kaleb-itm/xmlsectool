/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CommandLineArgumentsTest {

	@Test
	public void xstj34_sign_with_SHA256() throws Exception {
		final String[] args = {
				"--sign",
				"--inFile", "in.xml",
				"--outFile", "out.xml",
				"--certificate", "example.crt",
				"--key", "example.key"
				};
		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		final DigestChoice digest = cli.getDigest();
		Assert.assertNotNull(digest);
		Assert.assertSame(digest, DigestChoice.SHA256);
	}
	
	@Test
	public void xstj39_default_disallowed_SHA1() throws Exception {
		final String[] args = {
				"--sign",
				"--inFile", "in.xml",
				"--outFile", "out.xml",
				"--certificate", "example.crt",
				"--key", "example.key"
				};
		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		final DisallowedAlgorithms disallowed = cli.getDisallowedAlgorithms();
		Assert.assertTrue(disallowed.isDigestAlgorithmDisallowed(SignatureConstants.ALGO_ID_DIGEST_SHA1));
		Assert.assertTrue(disallowed.isSignatureAlgorithmDisallowed(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1));
		Assert.assertTrue(disallowed.isSignatureAlgorithmDisallowed(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1));
	}
}
