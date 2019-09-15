
package com.infotech.jwt.security;

import io.jsonwebtoken.JwtException;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * This filter is invoked by Zuul proxy and downstream microservices to authenticate the token if preset in request headers.
 */
public class JwtTokenFilter extends GenericFilterBean {

    private JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * Intercept requests for token validation.
     * @param req an instance of ServletRequest
     * @param res an instance of ServletResponse
     * @param filterChain an instance of FilterChain
     * @throws IOException an instance of IOException
     * @throws ServletException an instance of ServletException
     */
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
        Map<String,String> tokenDetails = jwtTokenProvider.resolveToken((HttpServletRequest) req);
        HttpServletRequest request = (HttpServletRequest) req;
		/*
		 * String requestId = request.getHeader(UMSAApplicationConstants.REQUEST_ID);
		 * if(requestId != null) { MDC.put("requestId", requestId); }
		 */

        if(tokenDetails != null) {
        String token  = tokenDetails.get("token");
            if (!"".equalsIgnoreCase(token) && null != token) {
                try {
                    jwtTokenProvider.validateToken(token);
                } catch (JwtException | IllegalArgumentException e) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
                    throw e;
                }
          }
            Authentication auth = token != null ? jwtTokenProvider.getAuthentication(token) : null;
            //setting auth in the context.
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(req, res);

    }
}