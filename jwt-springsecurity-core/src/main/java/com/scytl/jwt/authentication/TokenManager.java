/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 8:58:32 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.authentication;

import java.text.ParseException;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Manages tokens - separated from {@link AuthenticationService}, so we can
 * implement and plug various policies.
 */
public interface TokenManager {

    /**
     * Creates a new token for the user and returns its {@link TokenInfo}. It
     * may add it to the token list or replace the previous one for the user.
     * Never returns {@code null}.
     */
    TokenInfo createNewToken(UserDetails userDetails);

    /**
     * Returns user details for a token.
     * 
     * @throws JOSEException
     * @throws ParseException
     */
    UserDetails getUserDetails(String token);

}
