/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.logiclander.jaasmine;

/**
 *
 * @author tcarroll
 */
public enum AuthenticationType {

  KRB5("1.2.840.113554.1.2.2");
  private final String oid;

  AuthenticationType(String oid) {
    this.oid = oid;
  }

  public String getOidValue() {
    return oid;
  }
}
