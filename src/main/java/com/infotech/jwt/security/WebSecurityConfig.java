package com.infotech.jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import javax.servlet.http.HttpServletResponse;

/**
 * This class is used to enable Spring security and configure security attributes for the ZuulProxy service.
 */
@Order(1)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

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
                .antMatchers("/**login/**").permitAll()
                .antMatchers("/**organizations/**").permitAll()
                .antMatchers("/**users/emailId/**").permitAll()
                // Disallow everything else..
                .anyRequest().authenticated();

        // Apply JWT
        http.apply(new JwtTokenFilterConfigurer(jwtTokenProvider));
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
        web.ignoring().antMatchers("/*/")//
                .antMatchers("/*/register")//
                .antMatchers("/*/emailId")
                .antMatchers("/eureka/**")//
                .antMatchers(HttpMethod.OPTIONS, "/**"); // Request type options should be allowed.
    }
}

