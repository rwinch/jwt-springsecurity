/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 8:58:02 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.authentication;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

/** Contains information about a token. */
public final class TokenInfo {

    private final long _created = System.currentTimeMillis();

    private final String _token;

    private final UserDetails _userDetails;

    // TODO expiration etc

    public TokenInfo(final String token, final UserDetails userDetails) {
        _token = token;
        _userDetails = userDetails;
    }

    public String getToken() {
        return _token;
    }

    @Override
    public String toString() {
        return "TokenInfo{" + "token='" + _token + '\'' + ", userDetails"
            + _userDetails + ", created=" + new Date(_created) + '}';
    }
}
