package com.infotech.jwt.security;

import java.io.Serializable;

/**
 * Pojo class to represent JwtAuthenticationRequest.
 */
public class JwtAuthenticationRequest implements Serializable{

    private String userName;
    private String password;

    public JwtAuthenticationRequest() {
        super();
    }

    public JwtAuthenticationRequest(String userName, String password) {
        this.setUserName(userName);
        this.setPassword(password);
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
