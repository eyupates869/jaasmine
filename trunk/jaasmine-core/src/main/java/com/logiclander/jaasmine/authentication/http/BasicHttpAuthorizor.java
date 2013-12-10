package com.logiclander.jaasmine.authentication.http;

import java.util.List;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;

import com.google.common.collect.ImmutableList;
import com.logiclander.jaasmine.authentication.AuthenticationService;
import com.logiclander.jaasmine.authentication.SimpleAuthenticationService;

class BasicHttpAuthorizor extends BaseHttpAuthorizor {

    private final String appName;

    private final Subject subject;

    BasicHttpAuthorizor(HttpServletRequest httpRequest) {
        super(httpRequest);
        this.appName = AuthenticationService.DEFAULT_JAASMINE_LOGIN_CONFIG;
        this.subject = createSubject();
    }

    BasicHttpAuthorizor(HttpServletRequest httpRequest, String realmName) {
        super(httpRequest, realmName);
        this.appName = AuthenticationService.DEFAULT_JAASMINE_LOGIN_CONFIG;
        this.subject = createSubject();
    }

    BasicHttpAuthorizor(HttpServletRequest httpRequest, String realmName,
            String appName) {
        super(httpRequest, realmName);
        this.appName = appName;
        this.subject = createSubject();
    }

    private Subject createSubject() {
        List<String> credentials = getUsernamePasswordCreds(decodeAuthTokenCredentials());

        return doLogin(credentials);
    }

    private String decodeAuthTokenCredentials() {
        return new String(Base64.decodeBase64(authorizationToken()));
    }

    private List<String> getUsernamePasswordCreds(String decodedCredential) {

        ImmutableList.Builder<String> decodedCreds = ImmutableList.builder();
        for (String decodedCred : decodedCredential.split(":")) {
            decodedCreds.add(decodedCred);
        }

        if (decodedCreds.build().size() < 2) {
            decodedCreds.add("");
        }

        return decodedCreds.build();
    }

    private Subject doLogin(List<String> usernamePassword) {

        HttpSession session = getHttpRequest().getSession();

        Subject subj = (Subject) session
                .getAttribute(AuthenticationService.SUBJECT_KEY);

        if (subj == null) {
            AuthenticationService authnSvc = new SimpleAuthenticationService(
                    appName);

            subj = authnSvc.login(usernamePassword.get(0), usernamePassword
                    .get(1).toCharArray());

            if (subj != null) {
                session.setAttribute(AuthenticationService.SUBJECT_KEY, subj);
            }
        }

        return subj;
    }

    @Override
    public HttpServletRequest getAuthorizedHttpRequest() {
        return new JaasmineHttpServletRequest(getHttpRequest(), subject);
    }

    @Override
    public boolean isAuthorized() {
        return subject != null;
    }

}
