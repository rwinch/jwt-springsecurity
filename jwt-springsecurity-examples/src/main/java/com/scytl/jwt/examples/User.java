package com.scytl.jwt.examples;

import java.util.Set;

public class User {

    private String username;
    private String password;
    private Set<String> roles;

    public User() {
        
    }

    public User(String username, String password, Set<String> roles) {
        this.username = username;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public String getPassword() {
        return password;
    }
}
