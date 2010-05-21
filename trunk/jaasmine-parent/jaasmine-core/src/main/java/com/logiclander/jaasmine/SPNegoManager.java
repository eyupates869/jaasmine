/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
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
public class SPNegoManager {

  private final GSSContext gssContext;

  public SPNegoManager(Subject subject, String spn, AuthenticationType type)
          throws GSSException, PrivilegedActionException {
    // create a GSS Credential from a Subject that has Kerberos ticket(s)
    final Oid spnegoMechOid = new Oid(SPNEGO_MECH_OID);
    final GSSManager gssManager = GSSManager.getInstance();
    final GSSCredential gssClientCred = (GSSCredential) Subject.doAs(subject, new CredentialGenerator(gssManager, type.getOidValue()));
    // use the GSS Credential to create a SPNego Token and insert it into the HTTP header
    // create target server Service Principal Name (SPN)
    GSSName gssServerName = gssManager.createName(spn, GSSName.NT_USER_NAME);
    //GSSName gssServerName = manager.createName(spn,GSSName.NT_HOSTBASED_SERVICE,spnegoMechOid);
    gssContext = gssManager.createContext(gssServerName.canonicalize(spnegoMechOid), spnegoMechOid, gssClientCred, GSSContext.DEFAULT_LIFETIME);
    // enable GSS credential delegation
    gssContext.requestCredDeleg(true);
    // enable mutual authentication with server
    // context.requestMutualAuth(true);
  }

  public void dispose() throws GSSException {
    gssContext.dispose();
  }

  public boolean isNegotiated() {
    return gssContext.isEstablished();
  }

  public String generateSPNegoToken() throws GSSException {
    // create a SPNEGO token for the target server
    byte[] spnegoToken = new byte[0];
    spnegoToken = gssContext.initSecContext(spnegoToken, 0, spnegoToken.length);
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
