/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.logiclander.jaasmine;

import java.security.Principal;

import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSCredential;

/**
 *
 */
public class SPNegoPrincipal implements Principal {


    /** The KerberosPrincipal.*/
    private final KerberosPrincipal krbPrincipal;


    /** Credentials delegated from authentication.*/
    private final GSSCredential delegatedCred;


    /**
     *
     */
    public SPNegoPrincipal(final String name,
            final GSSCredential delegatedCred) {

        this.krbPrincipal = new KerberosPrincipal(name);
        this.delegatedCred = delegatedCred;
    }


    /**
     *
     * @return the principal name.
     */
    @Override
    public String getName() {
        return krbPrincipal.getName();
    }


    /**
     *
     * @return the delegated credential.
     */
    public GSSCredential getDelegatedCredential() {
        return delegatedCred;
    }
}
