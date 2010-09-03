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

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
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
public class SPNegoClient {

  private final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
  private final GSSManager gssManager = GSSManager.getInstance();
  private final GSSCredential gssClientCred;
  private boolean credentialDelegationState = true;
  private boolean mutualAuthenticationState = true;

  public SPNegoClient(Subject subject, AuthenticationType type)
          throws GSSException, PrivilegedActionException {
    // create a GSS Credential from a Subject that has Kerberos ticket(s)
    gssClientCred = (GSSCredential) Subject.doAs(subject, new CredentialGenerator(gssManager, type.getOidValue()));
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
    final GSSContext gssContext;
    byte[] spnegoToken = new byte[0];
    // create target server Service Principal Name (SPN)
    GSSName gssServerName = gssManager.createName(spn, GSSName.NT_USER_NAME);
    //GSSName gssServerName = manager.createName(spn,GSSName.NT_HOSTBASED_SERVICE,spnegoMechOid);
    // use the GSS Credential to create a SPNego Token for the target server
    gssContext = gssManager.createContext(gssServerName.canonicalize(spnegoMechOid), spnegoMechOid, gssClientCred, GSSContext.DEFAULT_LIFETIME);
    gssContext.requestCredDeleg(credentialDelegationState);
    gssContext.requestMutualAuth(mutualAuthenticationState);
    spnegoToken = gssContext.initSecContext(spnegoToken, 0, spnegoToken.length);
    gssContext.dispose();
    // return SPNegoToken to be inserted it into the HTTP header
    return new String(Base64.encodeBase64(spnegoToken));
  }

  private static class CredentialGenerator implements PrivilegedExceptionAction {

    private final GSSManager gssManager;
    private final Oid userMechOid;

    CredentialGenerator(GSSManager gssManager, String userMechOid) throws GSSException {
      this.gssManager = gssManager;
      this.userMechOid = new Oid(userMechOid);
    }

    @Override
    public GSSCredential run() throws GSSException {
      final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
      GSSCredential gssCred = gssManager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, userMechOid, GSSCredential.INITIATE_ONLY);
      gssCred.add(null, GSSCredential.INDEFINITE_LIFETIME, GSSCredential.INDEFINITE_LIFETIME, spnegoMechOid, GSSCredential.INITIATE_ONLY);
      return gssCred;
    }
  }
}
