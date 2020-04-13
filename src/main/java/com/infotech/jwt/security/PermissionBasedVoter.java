package com.infotech.jwt.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

/**
 * Cutsom voter class for AccessDecissionManager
 */
@Component
public class PermissionBasedVoter implements AccessDecisionVoter<Object> {

    /**
     * Autowiring to read role-access.yml file
     */
    @Autowired
    PermissionConfig permissionConfig;

    /**
     * @param authentication
     * @param object
     * @param collection
     * @return ACCESS_GRANTED – the voter gives an affirmative answer
     * ACCESS_DENIED – the voter gives a negative answer
     * ACCESS_ABSTAIN – the voter abstains from voting
     */
    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
                String requestMethod = request.getMethod();
                String requestUri = request.getRequestURI();

        /*boolean isRoleUser = authentication.getAuthorities().stream().peek(e-> System.out.println(e.getAuthority()))
                .filter(e -> e.getAuthority().equals("ROLE_STAFF"))
                .findAny().isPresent();*/

        String finalPermission = permissionConfig.getPermission(requestUri,requestMethod);
                return authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(r -> finalPermission.equalsIgnoreCase(r))
                        .findAny()
                        .map(s -> ACCESS_GRANTED)
                        .orElseGet(() -> ACCESS_DENIED);
    }


    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class aClass) {
        return true;
    }

}