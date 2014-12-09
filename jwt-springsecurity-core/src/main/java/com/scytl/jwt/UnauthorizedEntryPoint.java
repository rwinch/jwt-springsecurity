/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 9:01:07 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;


/**
 * {@link AuthenticationEntryPoint} that rejects all requests. Login-like
 * function is featured in {@link TokenAuthenticationFilter} and this does not
 * perform or suggests any redirection. This object is hit whenever user is not
 * authorized (anonymous) and secured resource is requested.
 */
@Component
public final class UnauthorizedEntryPoint implements
        AuthenticationEntryPoint {

    @Override
    public void commence(final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationException authException)
            throws IOException {
        response.sendError(HttpServletResponse.SC_NOT_FOUND);
    }
}
