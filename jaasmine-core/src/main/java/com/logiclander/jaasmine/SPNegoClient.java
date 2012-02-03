/*
 * Copyright 2010 LogicLander
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.logiclander.jaasmine;

import static com.logiclander.jaasmine.JAASMineContants.SPNEGO_MECH_OID;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 *
 * @author tcarroll
 */
public class SPNegoClient {

	private final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
	private final GSSManager gssManager = GSSManager.getInstance();
	private final GSSCredential gssClientCred;
	private boolean credentialDelegationState = true;
	private boolean mutualAuthenticationState = true;
	private final Log logger = LogFactory.getLog(SPNegoClient.class);

	public SPNegoClient(Subject subject, AuthenticationType type)
			throws GSSException, PrivilegedActionException {
		// create a GSS Credential using a JAAS Subject that has Kerberos
		// ticket(s)
		gssClientCred = Subject.doAs(
			subject,
			new CredentialGenerator(gssManager, type.getOidValue())
		);

	}

	public SPNegoClient(GSSCredential credential) throws GSSException {
		// use existing (perhaps delegated) credential
		gssClientCred = credential;
	}

	public boolean getCredentialDelegationState() {
		return credentialDelegationState;
	}

	// must be set prior to (initSecContext) generating first SPNegoToken
	public void setCredentialDelegationState(boolean state) throws GSSException {
		credentialDelegationState = state;
	}

	public boolean getMutualAuthenticationState() {
		return mutualAuthenticationState;
	}

	// must be set prior to (initSecContext) generating first SPNegoToken
	public void setMutualAuthenticationState(boolean state) throws GSSException {
		mutualAuthenticationState = state;
	}

	public String generateSPNegoToken(String spn) throws GSSException {

		String spnegoToken = "";
		if (gssClientCred == null) {

			if (logger.isDebugEnabled()) {
				logger.debug("No credential found, returning an empty String");
			}
			return spnegoToken;
		}

		GSSContext targetServerContext = null;

		try {

			GSSName targetSPN = createTargetSPN(spn);
			targetServerContext = createTargetServerContext(targetSPN);
			spnegoToken = createTargetSPNegoToken(targetServerContext);

			if (logger.isDebugEnabled()) {
				logger.debug(
					String.format("Generated SPNego token: %s", spnegoToken)
				);
			}

		} finally {

			if (targetServerContext != null) {

				if (logger.isDebugEnabled()) {
					logger.debug("Disposing targetServerContext");
				}
				targetServerContext.dispose();
			}
		}

		return spnegoToken;
	}

	private String createTargetSPNegoToken(GSSContext gssContext)
			throws GSSException {

		gssContext.requestCredDeleg(credentialDelegationState);
		gssContext.requestMutualAuth(mutualAuthenticationState);

		byte[] spnegoToken = new byte[0];
		spnegoToken = gssContext.initSecContext(
			spnegoToken,
			0,
			spnegoToken.length
		);

		return new String(Base64.encodeBase64(spnegoToken));
	}

	private GSSContext createTargetServerContext(GSSName gssServerName)
			throws GSSException {

		return gssManager.createContext(
			gssServerName.canonicalize(spnegoMechOid),
			spnegoMechOid,
			gssClientCred,
			GSSContext.DEFAULT_LIFETIME
		);
	}

	private GSSName createTargetSPN(String spn) throws GSSException {
		return gssManager.createName(spn, GSSName.NT_USER_NAME);
	}

	private static class CredentialGenerator implements
			PrivilegedExceptionAction<GSSCredential> {

		private final GSSManager gssManager;
		private final Oid userMechOid;

		CredentialGenerator(GSSManager gssManager, String userMechOid)
				throws GSSException {
			this.gssManager = gssManager;
			this.userMechOid = new Oid(userMechOid);
		}

		@Override
		public GSSCredential run() throws GSSException {
			final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
			GSSCredential gssCred = gssManager.createCredential(null,
					GSSCredential.DEFAULT_LIFETIME, userMechOid,
					GSSCredential.INITIATE_ONLY);
			gssCred.add(null, GSSCredential.INDEFINITE_LIFETIME,
					GSSCredential.INDEFINITE_LIFETIME, spnegoMechOid,
					GSSCredential.INITIATE_ONLY);
			return gssCred;
		}
	}
}
