/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 9:01:51 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Takes care of HTTP request/response pre-processing for login/logout and token
 * check. Login can be performed on any URL, logout only on specified
 * {@link #_logoutLink}. All the interaction with Spring Security should be
 * performed via {@link AuthenticationService}.
 * <p>
 * {@link SecurityContextHolder} is used here only for debug outputs. While this
 * class is configured to be used by Spring Security (configured filter on
 * FORM_LOGIN_FILTER position), but it doesn't really depend on it at all.
 */
@Component
public final class TokenLogoutFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory
        .getLogger(TokenLogoutFilter.class);

    private static final String DEFAULT_LOGOUT_PATH = "/logout";

    private static final String HEADER_TOKEN = "x-access-token";

    /**
     * Request attribute that indicates that this filter will not continue with
     * the chain. Handy after login/logout, etc.
     */
    private static final String REQUEST_ATTR_DO_NOT_CONTINUE =
        "TokenLogoutFilter-doNotContinue";

    private final String _logoutLink;

    private AuthenticationService authenticationService;

    public TokenLogoutFilter() {
        _logoutLink = DEFAULT_LOGOUT_PATH;

    }

    public TokenLogoutFilter(final String logoutLink) {
        _logoutLink = logoutLink;
    }

    @Override
    public void doFilter(final ServletRequest request,
            final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        LOGGER.info("TokenLogoutFilter.doFilter");
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        boolean authenticated = checkToken(httpRequest, httpResponse);

        if (canRequestProcessingContinue(httpRequest)) {
            if (httpRequest.getMethod().equals(HttpMethod.DELETE.name())) {
                // If we're not authenticated, we don't bother with logout at
                // all. Logout does not work in the same request with login -
                // this does not make sense, because logout works with token and
                // login returns it.
                if (authenticated) {
                    checkLogout(httpRequest, httpResponse);
                }
            }
        }

        if (canRequestProcessingContinue(httpRequest)) {
            chain.doFilter(request, response);
        }
        LOGGER.info("Authentication: "
            + SecurityContextHolder.getContext().getAuthentication());
    }

    /** Returns true, if request contains valid authentication token. */
    private boolean checkToken(final HttpServletRequest httpRequest,
            final HttpServletResponse httpResponse) throws IOException {
        String token = httpRequest.getHeader(HEADER_TOKEN);
        if (token == null) {
            return false;
        }

        if (authenticationService.checkToken(token)) {
            LOGGER.info(HEADER_TOKEN
                + " valid for: "
                + SecurityContextHolder.getContext().getAuthentication()
                    .getPrincipal());
            return true;
        } else {
            LOGGER.info("Invalid " + HEADER_TOKEN + " " + token);
            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
            doNotContinueWithRequestProcessing(httpRequest);
        }
        return false;
    }

    private void checkLogout(final HttpServletRequest httpRequest,
            final HttpServletResponse httpResponse) throws IOException {
        if (currentLink(httpRequest).equals(_logoutLink)) {
            String token = httpRequest.getHeader(HEADER_TOKEN);
            // we go here only authenticated, token must not be null
            authenticationService.logout(token);
            httpResponse.sendError(HttpServletResponse.SC_NO_CONTENT);
            doNotContinueWithRequestProcessing(httpRequest);
        }
    }

    // or use Springs util instead: new
    // UrlPathHelper().getPathWithinApplication(httpRequest)
    // shame on Servlet API for not providing this without any hassle :-(
    private String currentLink(final HttpServletRequest httpRequest) {
        if (httpRequest.getPathInfo() == null) {
            return httpRequest.getServletPath();
        }
        return httpRequest.getServletPath() + httpRequest.getPathInfo();
    }

    /**
     * This is set in cases when we don't want to continue down the filter
     * chain. This occurs for any {@link HttpServletResponse#SC_UNAUTHORIZED}
     * and also for login or logout.
     */
    private void doNotContinueWithRequestProcessing(
            final HttpServletRequest httpRequest) {
        httpRequest.setAttribute(REQUEST_ATTR_DO_NOT_CONTINUE, "");
    }

    private boolean canRequestProcessingContinue(
            final HttpServletRequest httpRequest) {
        return httpRequest.getAttribute(REQUEST_ATTR_DO_NOT_CONTINUE) == null;
    }

    public void setAuthenticationService(
            AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
}
