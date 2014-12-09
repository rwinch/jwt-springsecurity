/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 8:09:05 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.examples;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * This object wraps {@link com.scytl.ine.repository.model.entity.User} and
 * makes it {@link UserDetails} so that Spring Security can use it.
 */
@SuppressWarnings("serial")
public class UserContext implements UserDetails {

    private final User _user;

    public UserContext(final User user) {
        _user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (String role : _user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return _user.getPassword();
    }

    @Override
    public String getUsername() {
        return _user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(final Object o) {
        return this == o || o != null && o instanceof UserContext
            && Objects.equals(_user, ((UserContext) o)._user);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(_user);
    }

    @Override
    public String toString() {
        return "UserContext{" + "user=" + _user + '}';
    }
}
