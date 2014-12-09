/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 8:55:36 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.authentication;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * Service responsible for all around authentication, token checks, etc. This
 * class does not care about HTTP protocol at all.
 */
@Component(value = "SimpleAuthenticationService")
public class SimpleAuthenticationService implements AuthenticationService {

    private static final Logger LOGGER = LoggerFactory
        .getLogger(SimpleAuthenticationService.class);

    @Autowired
    private ApplicationContext _applicationContext;

    @Autowired
    private AuthenticationManager _authenticationManager;

    @Autowired
    private TokenManager _tokenManager;

    @PostConstruct
    public void init() {
        LOGGER.info("SimpleAuthenticationService.init with: "
            + _applicationContext);
    }

    @Override
    public TokenInfo authenticate(final String login, final String password) {
        LOGGER.info("SimpleAuthenticationService.authenticate");
        // Here principal=username, credentials=password
        Authentication authentication =
            new UsernamePasswordAuthenticationToken(login, password);
        try {
            authentication =
                _authenticationManager.authenticate(authentication);
            // Here principal=UserDetails (UserContext in our case),
            // credentials=null (security reasons)
            SecurityContextHolder.getContext().setAuthentication(
                authentication);
            if (authentication.getPrincipal() != null) {
                UserDetails userContext =
                    (UserDetails) authentication.getPrincipal();
                TokenInfo newToken =
                    _tokenManager.createNewToken(userContext);
                if (newToken == null) {
                    return null;
                }
                return newToken;
            }
        } catch (AuthenticationException e) {
            LOGGER.info("SimpleAuthenticationService.authenticate - FAILED: "
                + e.toString());
        } catch (IllegalArgumentException e) {
            LOGGER.info("SimpleAuthenticationService.authenticate - FAILED: "
                + e.toString());
        }
        return null;
    }

    @Override
    public boolean checkToken(final String token) {
        LOGGER.info("SimpleAuthenticationService.checkToken");
        UserDetails userDetails = null;
        try {
            userDetails = _tokenManager.getUserDetails(token);
        } catch (IllegalArgumentException e) {
            LOGGER.info("SimpleAuthenticationService.checkToken - FAILED: "
                + e.toString());
        }
        if (userDetails == null) {
            return false;
        }
        UsernamePasswordAuthenticationToken securityToken =
            new UsernamePasswordAuthenticationToken(userDetails, null,
                userDetails.getAuthorities());
        SecurityContextHolder.getContext()
            .setAuthentication(securityToken);

        return true;
    }

    @Override
    public void logout(final String token) {
        SecurityContextHolder.clearContext();
    }

    @Override
    public UserDetails currentUser() {
        Authentication authentication =
            SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        }
        return null;
    }
}
