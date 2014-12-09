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
import java.util.HashMap;
import java.util.Map;

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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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
public final class TokenAuthenticationFilter extends GenericFilterBean {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String HEADER_TOKEN = "x-access-token";

    private static final Logger LOGGER = LoggerFactory
        .getLogger(TokenAuthenticationFilter.class);

    private static final String DEFAULT_TOKEN_RESPONSE =
        "{\"token\" : \"%s\"}";

    /**
     * Request attribute that indicates that this filter will not continue with
     * the chain. Handy after login/logout, etc.
     */
    private static final String REQUEST_ATTR_DO_NOT_CONTINUE =
        "TokenAuthenticationFilter-doNotContinue";

    private AuthenticationService authenticationService;

    @Override
    public void doFilter(final ServletRequest request,
            final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        LOGGER.debug("TokenAuthenticationFilter.doFilter");
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        boolean authenticated = checkToken(httpRequest, httpResponse);

        if (canRequestProcessingContinue(httpRequest)) {

            if (httpRequest.getMethod().equals(HttpMethod.POST.name())) {
                if(!authenticated) {
                    checkLogin(httpRequest, httpResponse);
                }
            }
        }

        if (canRequestProcessingContinue(httpRequest)) {
            chain.doFilter(request, response);
        }
        LOGGER.debug("Authentication: "
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
    
    private void checkLogin(final HttpServletRequest httpRequest,
            final HttpServletResponse httpResponse) throws IOException {
        String username = null;
        String password = null;
        Map<String, String> content;
        try {
            content =
                OBJECT_MAPPER.readValue(httpRequest.getInputStream(),
                    new TypeReference<HashMap<String, Object>>() {});
            
            username = content.get("username");
            password = content.get("password");
        } catch (JsonMappingException e) {
            LOGGER.error("Authentication: Could not map username and/or password");
            throw new IllegalArgumentException(e);
        }

        if (username != null && password != null) {
            checkUsernameAndPassword(username, password, httpResponse);
            doNotContinueWithRequestProcessing(httpRequest);
        }
    }

    private void checkUsernameAndPassword(final String username,
            final String password, final HttpServletResponse httpResponse)
            throws IOException {
        TokenInfo tokenInfo =
            authenticationService.authenticate(username, password);
        if (tokenInfo != null) {
            httpResponse.setStatus(HttpServletResponse.SC_OK);
            httpResponse.getWriter()
                .write(
                    String.format(DEFAULT_TOKEN_RESPONSE,
                        tokenInfo.getToken()));
            httpResponse.getWriter().flush();
            httpResponse.getWriter().close();

        } else {
            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
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
