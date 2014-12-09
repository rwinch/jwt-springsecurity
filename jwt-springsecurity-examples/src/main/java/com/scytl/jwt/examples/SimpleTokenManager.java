/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 9:10:26 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.examples;

import java.text.ParseException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.scytl.jwt.authentication.TokenInfo;
import com.scytl.jwt.authentication.TokenManager;

/**
 * Implements simple token manager, that keeps a single token for each user. If
 * user logs in again, older token is invalidated.
 */
@Component
public class SimpleTokenManager implements TokenManager {

    private static final Logger LOGGER = LoggerFactory
        .getLogger(SimpleTokenManager.class);

    @Autowired
    private UserDetailsService _userDetailsService;

    @Override
    public TokenInfo createNewToken(final UserDetails userDetails) {
        LOGGER.debug("Create new token for user: " + userDetails.getUsername());
        String token;
        try {
            token = generateToken(userDetails);
        } catch (JOSEException e) {
            throw new IllegalArgumentException(e);
        }
        return new TokenInfo(token, userDetails);

    }

    private String generateToken(final UserDetails userDetails)
            throws JOSEException {
        JWSSigner signer = new MACSigner(SharedSecret.getSecret());
        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setSubject(userDetails.getUsername());
        claimsSet.setIssueTime(new Date());
        SignedJWT signedJWT =
            new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    @Override
    public UserDetails getUserDetails(final String token) {
        LOGGER.debug("Get user details from token: " + token);
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(SharedSecret.getSecret());
            try {
                if (signedJWT.verify(verifier)) {
                    String username = signedJWT.getJWTClaimsSet().getSubject();
                    return _userDetailsService.loadUserByUsername(username);
                } else {
                    throw new IllegalArgumentException("Firm is not verified.");
                }
            } catch (UsernameNotFoundException | JOSEException e) {
                throw new IllegalArgumentException(e);
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
