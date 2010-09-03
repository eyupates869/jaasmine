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
 */
public class SPNegoAuthenticationServer {

    
    /** An empty byte array to return (avoids null pointer exceptions).*/
    private transient static final byte[] EMPTY_BYTE_ARRAY = new byte[0];


    /** The logger for this instance.*/
    private transient final Log logger = LogFactory.getLog(SPNegoAuthenticationServer.class);


    /** The GSSManager.*/
    private transient final GSSManager manager = GSSManager.getInstance();


    /** The GSSCredential for this instance. */
    private transient final GSSCredential sPNegoServerCred;

    /** The object identity for this instance.*/
    private transient final Oid sPNegoOid;


    /** A peer token, generated when the doAuthentication method is called.*/
    private transient byte[] peerToken = EMPTY_BYTE_ARRAY;


    /**
     * Constructs a new SPNegoServer.
     * 
     * @throws GSSException if a GSSException is thrown during construction.
     */
    public SPNegoAuthenticationServer() throws GSSException {

        sPNegoOid = new Oid(JAASMineContants.SPNEGO_MECH_OID);

        sPNegoServerCred = manager.createCredential(
                null,
                GSSCredential.DEFAULT_LIFETIME,
                sPNegoOid,
                GSSCredential.ACCEPT_ONLY
            );
    }


    /**
     * Authenticates the given token by returning a SPNegoPrincipal.  If the
     * token can't be authenticated, this method returns null.
     *
     * Note:  one side-effect of calling this method is that a peer token is
     * populated when authentication occurs.  This is meant to be returned to
     * the client.
     *
     * @param authToken the base64 token
     * @return a SPNegoPrincipal if the token can be authenticated or null
     * otherwise.
     * @throws GSSException if a GSSException is thrown during the
     * authentication process.
     */
    public SPNegoPrincipal doAuthentication(String authToken)
            throws GSSException {

        byte[] token = decodeToken(authToken);
        if (token.length == 0) {
            logger.debug("No auth token specified");
            return null;
        }

        GSSContext context = manager.createContext(sPNegoServerCred);

        peerToken = context.acceptSecContext(token, 0, token.length);
        
        if (!context.isEstablished()) {
            logger.debug("Failed to establish context");
            return null;
        }

        String principal = context.getSrcName().toString();

        GSSCredential delegated = null;
        if (context.getCredDelegState()) {
            delegated = context.getDelegCred();
        }

        return new SPNegoPrincipal(principal, delegated);
    }


    /**
     * Returns the Base64 encoded peer token generated when
     * {@link #doAuthentication(java.lang.String) doAuthentication} was called.
     *
     * If {@link #doAuthentication(java.lang.String) doAuthentication} was not
     * called, this returns an empty String.
     *
     * @return a Base64 encoded String (suitable for HTTP headers).
     */
    public String getPeerToken() {

        if (peerToken == EMPTY_BYTE_ARRAY || peerToken.length == 0) {
            logger.debug("peer token not generated");
        }
        
        return Base64.encodeBase64String(peerToken);
    }


    /**
     * Generates and returns a SPNego token for the given server principal
     * from the given SPNegoPrincipal.
     *
     * If the SPNegoPrincipal does not contain a delegated credential, this
     * method returns null.
     *
     * @param serverPrincipal the target server
     * @param principal the SPNegoPrincipal containing a delegated credential.
     * @return a Base64 encoded String to be used as a SPNego token.
     * @throws GSSException if a GSSException occurs during processing.
     */
    public String getDelegatedSPNegoToken(String serverPrincipal,
            SPNegoPrincipal principal) throws GSSException {

        GSSCredential delegated = principal.getDelegatedCredential();
        if (delegated == null) {
            logger.debug("Credentials not delegated");
            return null;
        }

        GSSName serverName = manager.createName(serverPrincipal, sPNegoOid);
        GSSContext delegateContext =
                manager.createContext(
                    serverName,
                    sPNegoOid,
                    delegated,
                    GSSContext.DEFAULT_LIFETIME
                );
        delegateContext.requestCredDeleg(true);
        
        byte[] delegatedToken = new byte[0];
        delegatedToken =
                delegateContext.initSecContext(
                    delegatedToken, 
                    0,
                    delegatedToken.length
                );

        return new String(Base64.encodeBase64(delegatedToken));
    }


    /**
     * Decodes the given Base64-encoded String into a byte array.  If the String
     * is null or empty, an empty byte array is returned.
     *
     * @param encodedBase64 the String to convert to a byte array.
     * @return the decoded byte array.
     */
    private byte[] decodeToken(String encodedBase64) {

        if (encodedBase64 == null || encodedBase64.isEmpty()) {
            return EMPTY_BYTE_ARRAY;
        } else {
            return Base64.decodeBase64(encodedBase64);
        }
    }

}
