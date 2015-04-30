

# Getting Started #
Services running on UNIX systems can be configured with service instance accounts in ActiveDirectory; however, unlike Kerberos principal names, ActiveDirectory account names do not have multiple parts, so it is not possible to directly create an account like HTTP/myservice1.yourdomain.com.  Instead, this is accomplished by using Service Principal Name (SPN) mappings, so JAASmine use cases may require one or more of the following:

## create an ActiveDirectory account ##
create an ActiveDirectory account using the active directory users and computers administration application.

you can create either a computer or user account.  there are no strict rules about when to use either one, but there are some considerations that may lead you to choose one over the other:
  1. computer accounts do not have associated passwords, so an authentication credential will require a keytab; whereas user accounts have a traditional principal/password credential that can facilitate interactive authN or programmatic authN like basic auth and otherwise.
  1. computer accounts have a minimal number of attributes; whereas user accounts have many associated attributes like firstname, lastname, middlename, emailaddress, etc.  some automation accounts may not have sensible values for these attributes (although, some of them can be left blank, as we'll demonstrate later).
  1. computer accounts do not support the des-cbc-md5 encryption type; when your service requires this type, you must choose a user account.
  1. user accounts can be used to login to windows workstations for various purposes, including password changes; therefore, it is important to note that changing a password on a user account will invalidate a keytab, so user accounts with keytabs have a higher risk of inadvertent human error reeking havoc in a way that is not easy to troubleshoot.

other points of interest:
  * all ActiveDirectory computer accounts are suffixed with the "$" behind the scenes, so when referring to them using command line utilities, the "$" will need to be included.  for example, a computer account created as myservice1 will be referenced in command line utilities as myservice1$.  don't ask me why... stupid! did i say that out loud?
  * the ActiveDirectory account name (NetBIOS name) is limited to 15 characters.  the ActiveDirectory users and computers administration application will allow you to create longer names; however, you will need to use the truncated "pre-Windows 2000" name when using the ktpass, setspn, and other command line utilities.  therefore, we recommend adhering to the 15 character limit to avoid confusion.

## map Account to SPN ##
create a service principal name (SPN) mapping (to an ActiveDirectory acount) using the setspn windows command line utility.  it is important to note that the ktpass utility (discussed below) also has options to create this mapping as part of the keytab generation process.

using setspn.exe:
```
LIST (inspect) MAPPINGS:
syntax - setspn -l activedirectory-account
sample - setspn -l myservice1

ADD new MAPPING:
syntax - setspn -a service/host.yourdomain.com activedirectory-account
sample - setspn -a ldap/service.yourdomain.com myservice1

REMOVE existing MAPPING:
syntax - setspn -d service/host.yourdomain.com activedirectory-account
sample - setspn -d ldap/service.yourdomain.com myservice1

RESET MAPPINGS:
syntax - setspn -r activedirectory-account
sample - setspn -r myservice1
```

other points of interest:
  * the "reset" mapping function is a bit mysterious.  i believe it is suppose to put the account back to the original creation state with regard to SPN mappings; however, interestingly the reset mapping function adds default SPNs that are not there when the account is created new.  these default mappings are typically not added until the account is bound to the AD (i.e. first connection).
  * Updating SPNs is rarely required (i.e. computer name change, requires the SPNs for installed services to be changed to match it.)

## create a keytab ##
create the Kerberos keytab file using the ktpass windows command line utility to be used by UNIX Kerberos-based systems to define KDC hosts and user/service mappings.  Keytab files can be used in conjunction with a Kerberos account to prove identity in an authentication sequence.  it is important to note that the ktpass utility has options for creating the service principal name (SPN) mapping (also described above).

The ktpass command-line tool enables configuration of a non-Windows server Kerberos service as a security principal in the AD. ktpass configures the server principal name for the host or service in AD and generates an MIT-Kerberos style "keytab" file that contains the shared secret key of the service. The tool allows UNIX-based services that support Kerberos authN to use the interoperability features of the AD Kerberos KDC.  In other words, MIT Kerberos clients and servers on UNIX systems can authenticate against the AD Kerberos server, and clients connected to Windows servers can authenticate to Kerberos services that support GSS API.

using ktpass.exe:
  * http://support.microsoft.com/kb/324144
  * http://technet.microsoft.com/en-us/library/cc753771%28v=ws.10%29.aspx

other points of interest:
  * There are several quirks and defects in the ktpass utility; however, there is one that has caused us a good deal of grief and deserves mention.  As detailed [here](http://support.microsoft.com/default.aspx?scid=kb;EN-US;939980), using the option to prompt for a password to be used in the keytab is problematic.  In order to achieve the desired result, the password must be entered directly on the command line.
  * When creating a keytab for a user account, including "-ptype KRB5\_NT\_PRINCIPAL" will suppress an annoying warning message ("WARNING: pType and account type do not match. This might cause  problems."); this message cannot be avoided when generating keytabs for computer accounts.
  * When creating a keytab for a user account, including "+setupn" and "+setpass" will ensure that the UPN password, SPN password, and keytab passphrase are all set to the same value, allowing ongoing authN success in apps that use those credential combinations (UPN equates to ActiveDirectory account)
  * It does not appear that you can map multiple service instances to the same ActiveDirectory user account.  I believe this is due to the complications of setting and resetting the passwords or pass-phrases associated with each of those individual accounts.  Although there are some differing speculations about this.  References on mapping multiple SPNs to one account: [seemingly clear support](http://msdn.microsoft.com/en-us/library/windows/desktop/ms677601(v=VS.85).aspx), [less clear support](http://msdn.microsoft.com/en-us/library/windows/desktop/ms677949(v=VS.85).aspx), [clearly not supporting](http://technet.microsoft.com/en-us/library/cc753771(WS.10).aspx).

## apply the keytab file ##
After you generate the keytab file, there are three options for applying for use via JAASmin:
  1. replace the default unix keytab (i.e. /etc/krb5.keytab)
  1. merge the new file with the default unix keytab (i.e. /etc/krb5.keytab) using the ktutil unix command line tool.
  1. copy keytab to location (i.e. `$CATALINA_BASE/conf`) referenced by `jaas.conf` as described below

## create jaas.conf ##
  1. configure `jaas.conf` to accept SPNego tokens (see sample file below)
  1. copy `jaas.conf` to `$CATALINA_BASE/conf`

```
...

/*
 * This module is configured using the default name.  At a minimum, it uses the
 * com.sun.security.auth.module.Krb5LoginModule module class with the required
 * flag set.
 */
jaasmine.login {
    com.sun.security.auth.module.Krb5LoginModule
    required;
};

/*
 * This is the configuration needed to support SPNego token validation.
 *
 * The com.sun.security.auth.module.Krb5LoginModule module class should be used
 * with the required flag set.  The following module options should be set:
 *
 * principal - a quoted string that is the server principal name
 * storeKey  - set this to true
 * useKeyTab - set this to true
 * keyTab    - a quoted string that is the absolute path to the keytab file.
 */
com.sun.security.jgss.krb5.accept {
    com.sun.security.auth.module.Krb5LoginModule
    required
    principal="HTTP/machine-name.yourdomain.edu@AD.YOURDOMAIN.EDU"
    storeKey=true
    useKeyTab=true
    keyTab="/path/to/file/service-username.keytab";
};

...
```

**NOTE:** the principal must match the SPN specified in the keytab created above

## create krb5.conf ##
  1. configure `krb5.conf` to accept SPNego tokens (see sample file below)
  1. copy `krb5.conf` to `$CATALINA_BASE/conf`

```
...

[libdefaults]
default_realm = AD.YOURDOMAIN.EDU
forwardable = true
proxiable = true

[realms]
AD.YOURDOMAIN.EDU = {
 kdc = ad-dc-p1.ad.yourdomain.edu
 kdc = ad-dc-p2.ad.yourdomain.edu
 admin_server = ad-dc-p1.ad.yourdomain.edu
 }

...
```

## create setenv.sh ##
  1. configure `setenv.sh` to take the system props needed for krb5 authN (see sample file below)
  1. copy `setenv.sh` to `$CATALINA_BASE/bin`

```
...

# Enable JAAS/KRB5 authN/authZ
CATALINA_OPTS="$CATALINA_OPTS -Djava.security.krb5.conf=/path/to/file/krb5.conf"
CATALINA_OPTS="$CATALINA_OPTS -Djava.security.auth.login.config=/path/to/file/jaas.conf"

# Enable debugging of Sun's krb5 login module & GSSAPI
CATALINA_OPTS="$CATALINA_OPTS -Dsun.security.krb5.debug=true"
CATALINA_OPTS="$CATALINA_OPTS -Dsun.security.jgss.debug=true"

# From <URL:http://forums.oracle.com/forums/thread.jspa?threadID=867326>
CATALINA_OPTS="$CATALINA_OPTS -Djavax.security.auth.useSubjectCredsOnly=false"

export CATALINA_OPTS

# Path to file containing the process ID of catalina java process
CATALINA_PID=/path/to/file/tomcat.pid
export CATALINA_PID

...
```

**NOTE:** the path to `java.security.krb5.conf` will vary

**NOTE:** the path to `java.security.auth.login.config` will vary

**NOTE:** the path to `CATALINA_PID` will vary

# Applying JAASmine #

## Securing Web Services ##
  1. Follow the steps in the [JAASmineUsersGuide#Getting\_Started](JAASmineUsersGuide#Getting_Started.md) section for your server.
  1. Deploy _jaasmine-core.jar_ with your web application or in the application server's shared/common classloader.
  1. Add this servlet filter in your _WEB-INF/web.xml_ file:
```
    <filter>
        <filter-name>SPNegoFilter</filter-name>
        <filter-class>com.logiclander.jaasmine.authentication.http.SPNegoFilter</filter-class>
    </filter>
```
  1. Set up the appropriate filter-mappings for your application's web services.  Be sure to map all the url-patterns to your web services.
  1. Restart Tomcat.

## Securing uPortal ##

## Securing Kuali Rice ##
  1. add JAAS & krb5 config for accepting SPNego tokens
  1. add a keytab file
  1. update setenv.sh to take the system props needed for krb5 authn
  1. disable Location directive for Apache/Bluestem
  1. De(velop/ploy) custom rice `LoginFilter`
  1. add `JAASmine` login filter
  1. configure `web.xml` for rice
  1. update `rice-config.xml` to use the `LoginFilter` (see sample file below)
  1. restart tomcat

```
...

  <param name="filter.SPNegoLoginFilter.class">com.logiclander.jaasmine.authentication.http.SPNegoFilter</param>
  <param name="filtermapping.SPNegoLoginFilter.1">/remoting/*</param>
  <param name="filter.JaasLoginFilter.class">com.logiclander.jaasmine.authentication.http.JaasLoginFilter</param>
  <param name="filter.JaasLoginFilter.loginPath">/WEB-INF/jsp/login.jsp</param>
  <param name="filtermapping.JaasLoginFilter.2">/*</param-->

...
```

# Supporting and Otherwise Interesting References #
  * http://technet.microsoft.com/en-us/library/bb742433.aspx
  * https://wiki.cites.uiuc.edu/wiki/x/GSZkAg
  * http://www.ietf.org/rfc/rfc4559.txt
  * http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/lab/part5.html
  * http://pic.dhe.ibm.com/infocenter/wasinfo/v7r0/index.jsp?topic=/com.ibm.websphere.express.doc/info/exp/ae/tsec_SPNEGO_token.html
  * http://docs.oracle.com/javase/1.4.2/docs/guide/security/jaas/spec/
  * http://www.drdobbs.com/ssh-kerberos-authentication-using-gssapi/184402071
  * http://docs.oracle.com/javase/1.5.0/docs/guide/security/jgss/tutorials/BasicClientServer.html
  * http://stackoverflow.com/questions/435091/is-a-service-principal-name-spn-bound-to-a-specific-machine
  * http://msdn.microsoft.com/en-us/library/ms995352.aspx
  * http://support.microsoft.com/kb/929650
  * http://blog.msfirewall.org.uk/2008/07/publishing-exchange-2007-services-with.html
  * http://s2.diffuse.it/blog/show/6602-SPNEGO_authentication_and_credential_delegation_with_Java