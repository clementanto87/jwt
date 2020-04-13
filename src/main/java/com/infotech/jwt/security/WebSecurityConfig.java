package com.infotech.jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

/**
 * This class is used to enable Spring security and configure security attributes for the ZuulProxy service.
 */
@Order(1)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private PermissionBasedVoter permissionBasedVoter;

    /**
     * This method configures security attributes.
     *
     * @param http an instance of HttpSecurity
     * @throws Exception an instance of Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Disable CSRF (cross site request forgery)
        http.cors().and().csrf().disable();

        // No session will be created or used by spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED));

        // Entry points
        http.authorizeRequests()
                /*.antMatchers("/**test/**").hasRole("ADMIN1")*/
                .antMatchers("/**login/**").permitAll()
                .antMatchers("/**organizations/**").permitAll()
                .antMatchers("/**users/emailId/**").permitAll()
                // Disallow everything else..
                .anyRequest().authenticated();

        // Apply JWT
        http.apply(new JwtTokenFilterConfigurer(jwtTokenProvider));

        http.authorizeRequests()
                .accessDecisionManager(accessDecisionManager(permissionBasedVoter));
    }

    /**
     * Overrride default AccessDecisionManager provided by springsecurity
     * in order to implement custom voter- permissionBasedVoter
     * @return AccessDecisionManager object
     */
    @Bean
    public AccessDecisionManager accessDecisionManager(PermissionBasedVoter permissionBasedVoter) {
        List<AccessDecisionVoter<? extends Object>> decisionVoters
                = Arrays.asList(
                new WebExpressionVoter(),
                new RoleVoter(),
                new AuthenticatedVoter(),
                permissionBasedVoter);
        return new UnanimousBased(decisionVoters);
    }


    /**
     * This method allows to configure web security attributes.
     *
     * @param web an instance of WebSecurity
     * @throws Exception an instance of Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // Allow eureka client to be accessed without authentication
        web.ignoring().antMatchers("/*/")
                .antMatchers("/*/register")
                .antMatchers("/*/emailId")
                .antMatchers("/login/**")
                .antMatchers(HttpMethod.OPTIONS, "/**"); // Request type options should be allowed.
    }
}

