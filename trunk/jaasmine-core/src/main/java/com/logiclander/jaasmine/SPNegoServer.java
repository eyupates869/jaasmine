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
public class SPNegoServer {

	/** An empty byte array to return (avoids null pointer exceptions). */
	private transient static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
	private final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
	private final GSSManager gssManager = GSSManager.getInstance();
	private final GSSCredential gssServerCred;
	private final byte[] responseToken;
	private final boolean isValidToken;
	private final boolean canDelegateToken;
	private final GSSCredential gssDelegateCred;

	private final GSSName requesterName;

	private final Log logger = LogFactory.getLog(SPNegoServer.class);

	public SPNegoServer(String spnegoToken) throws GSSException {

		GSSContext gssContext = null;

		try {

			gssServerCred = createServerCredential();
			gssContext = createServerContext(gssServerCred);
			responseToken = createResponseToken(gssContext, spnegoToken);

			isValidToken = gssContext.isEstablished();

			canDelegateToken = gssContext.getCredDelegState();
			gssDelegateCred = getDelegateCredential(gssContext);

			requesterName = gssContext.getSrcName();

		} finally {

			if (gssContext != null) {

				if (logger.isDebugEnabled()) {
					logger.debug("Disposing context");
				}
				gssContext.dispose();
			}

		}
	}

	private GSSCredential getDelegateCredential(GSSContext ctx)
			throws GSSException {

		GSSCredential delegate = null;

		if (canDelegateToken) {
			delegate = ctx.getDelegCred();
		}

		return delegate;
	}

	private GSSContext createServerContext(GSSCredential serverCredential)
			throws GSSException {
		return gssManager.createContext(serverCredential);
	}

	private GSSCredential createServerCredential() throws GSSException {
		return gssManager.createCredential(null,
				GSSCredential.DEFAULT_LIFETIME, spnegoMechOid,
				GSSCredential.ACCEPT_ONLY);
	}

	private byte[] createResponseToken(GSSContext ctx, String spnegoToken)
			throws GSSException {

		byte[] spnegoTokenBytes = Base64.decodeBase64(spnegoToken);
		return ctx.acceptSecContext(spnegoTokenBytes, 0,
				spnegoTokenBytes.length);
	}

	public boolean isValidToken() {
		return isValidToken;
	}

	public boolean canDelegateToken() {
		return canDelegateToken;
	}

	public GSSCredential getDelegatedCredential() {
		return gssDelegateCred;
	}

	public byte[] getResponseToken() {
		return responseToken;
	}

	public GSSName getRequesterName() throws GSSException {
		return requesterName;
	}

	public String generateDelegateSPNegoToken(String spn) throws GSSException {
		SPNegoClient client = new SPNegoClient(gssDelegateCred);
		return client.generateSPNegoToken(spn);
	}

}
