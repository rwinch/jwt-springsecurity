/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 8:04:38 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.examples;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static List<User> users = new ArrayList<User>();
    
    {
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        User user = new User("admin", "adm1n", roles);
        users.add(user);
    }
    
    /**
     * This will be called from
     * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider#retrieveUser(java.lang.String, org.springframework.security.authentication.UsernamePasswordAuthenticationToken)}
     * when
     * {@link AuthenticationService#authenticate(java.lang.String, java.lang.String)}
     * calls
     * {@link AuthenticationManager#authenticate(org.springframework.security.core.Authentication)}
     * . Easy.
     */
    @Override
    public UserDetails loadUserByUsername(final String username)
            throws UsernameNotFoundException {
        User user = findUserByUserName(username);
        if (user == null) {
            throw new UsernameNotFoundException("User " + username
                + " not found");
        }
        return new UserContext(user);
    }
    
    private User findUserByUserName(String name) {
        for (User user : users) {
            if(user.getUsername().equals(name)) {
                return user;
            }
        }
        return null;
    }
}
