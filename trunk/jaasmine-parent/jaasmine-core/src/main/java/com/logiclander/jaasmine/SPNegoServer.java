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
import org.ietf.jgss.Oid;

/**
 *
 * @author tcarroll
 */
public class SPNegoServer {
  private final GSSContext gssContext;
  private byte[] delegateToken = null;

  public SPNegoServer(String authenticationHeader)
         throws GSSException {
    final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
    final GSSManager gssManager = GSSManager.getInstance();

    final GSSCredential gssServerCred = gssManager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, spnegoMechOid, GSSCredential.ACCEPT_ONLY);
    gssContext = gssManager.createContext(gssServerCred);

    byte[] token = Base64.decode(authenticationHeader);
    delegateToken = gssContext.acceptSecContext(token, 0, token.length);

  }

  public boolean isValid()
          throws GSSException {
    if(gssContext.isEstablished()) {
      return true;
    } else {
      return false;
    }
  }

  public byte[] getDelegateToken() {
    return delegateToken;
  }
}
