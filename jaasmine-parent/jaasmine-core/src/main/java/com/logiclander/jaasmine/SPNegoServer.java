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

import static com.logiclander.jaasmine.JAASMineContants.*;

import org.apache.commons.codec.binary.Base64;
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

  /** An empty byte array to return (avoids null pointer exceptions).*/
  private transient static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
  private final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
  private final GSSManager gssManager = GSSManager.getInstance();
  private final GSSCredential gssServerCred;
  private final byte[] responseToken;
  private final boolean isValidToken;
  private final boolean canDelegateToken;
  private final GSSCredential gssDelegateCred;

  public SPNegoServer(String spnegoToken)
          throws GSSException {
    gssServerCred = gssManager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, spnegoMechOid, GSSCredential.ACCEPT_ONLY);
    final GSSContext gssContext;
    gssContext = gssManager.createContext(gssServerCred);
    byte[] requestToken = Base64.decodeBase64(spnegoToken);
    responseToken = gssContext.acceptSecContext(requestToken, 0, requestToken.length);
    isValidToken = gssContext.isEstablished();
    canDelegateToken = gssContext.getCredDelegState();
    if (canDelegateToken) {
        gssDelegateCred = gssContext.getDelegCred();
    } else {
        gssDelegateCred = null;
    }
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

  public byte[] generateDelegateToken(String spn)
         throws GSSException {
     if (gssDelegateCred == null) {
      return EMPTY_BYTE_ARRAY;
    }
    GSSName gssServerName = gssManager.createName(spn, GSSName.NT_USER_NAME);
    final GSSContext delegateContext;
    delegateContext = gssManager.createContext(gssServerName.canonicalize(spnegoMechOid), spnegoMechOid, gssDelegateCred, GSSContext.DEFAULT_LIFETIME);
    byte[] delegateToken = new byte[0];
    delegateToken = delegateContext.initSecContext(delegateToken, 0, delegateToken.length);
    return delegateToken;
  }
}
