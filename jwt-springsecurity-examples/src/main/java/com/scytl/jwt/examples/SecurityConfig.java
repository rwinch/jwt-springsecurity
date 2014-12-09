/**
 * $Id$
 * @author rredondo
 * @date   Nov 28, 2014 8:02:48 AM
 *
 * Copyright (C) 2014 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.jwt.examples;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.scytl.jwt.authentication.AuthenticationService;
import com.scytl.jwt.authentication.TokenAuthenticationFilter;
import com.scytl.jwt.authentication.TokenLogoutFilter;

/**
 *
 */
@Configuration
@EnableWebMvcSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
@ComponentScan(basePackages = {"com.scytl.jwt" })
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService _customUserDetailsService;

    @Autowired
    private AuthenticationEntryPoint _unauthorizedEntryPoint;

    @Autowired
    private TokenAuthenticationFilter _tokenAuthenticationFilter;

    @Autowired
    private TokenLogoutFilter _tokenLogoutFilter;
    
    @Autowired
    @Qualifier("SimpleAuthenticationService")
    private AuthenticationService _authenticationService;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean()
            throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    @Autowired
    public void configure(final AuthenticationManagerBuilder auth)
            throws Exception {
        auth.userDetailsService(_customUserDetailsService);
        _tokenAuthenticationFilter.setAuthenticationService(_authenticationService);
        _tokenLogoutFilter.setAuthenticationService(_authenticationService);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(
            SessionCreationPolicy.STATELESS);
        http.httpBasic().authenticationEntryPoint(_unauthorizedEntryPoint);
        http.addFilterBefore(_tokenAuthenticationFilter,
            UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(_tokenLogoutFilter, LogoutFilter.class);
        http.authorizeRequests().antMatchers("/**").fullyAuthenticated();
    }
}
