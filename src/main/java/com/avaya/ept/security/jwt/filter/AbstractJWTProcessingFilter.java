/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.jwt.filter;

import static com.avaya.ept.security.jwt.util.HttpHeadersConstants.HEADER_STRING;
import static com.avaya.ept.security.jwt.util.HttpHeadersConstants.JWT_TOKEN_PREFIX;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import lombok.extern.slf4j.Slf4j;

/**
 * Abstract filtering class for JWT tokens
 * 
 * @author vhrodriguesv
 */
@Slf4j
public abstract class AbstractJWTProcessingFilter extends GenericFilterBean implements JWTProcessingFilter {

    /*
     * The URL filter pattern
     */
    private final String urlFilter;

    public AbstractJWTProcessingFilter(String urlFilter) {
        this.urlFilter = urlFilter;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) {
        try {
            HttpServletRequest servletRequest = (HttpServletRequest) request;
            String requestURI = servletRequest.getRequestURI();
            log.debug("AbstractJWTProcessingFilter.doFilter received requestURI: " + requestURI + " and urlFilter: " + urlFilter);
            // validates URL is configured to the filter
            if (requestURI != null && requestURI.contains(urlFilter)) {
                // now it should validate the token, otherwise should fail the authentication
                String authorizationHeader = servletRequest.getHeader(HEADER_STRING);
                // if authorization header is empty, then exception
                if (StringUtils.isEmpty(authorizationHeader)) {
                    throw new BadCredentialsException("JWT authentication failed, no authorization header was sent.");
                }
                if (authorizationHeader != null && authorizationHeader.contains(JWT_TOKEN_PREFIX)) {
                    String jwtToken = authorizationHeader.substring(JWT_TOKEN_PREFIX.length()).trim();
                    // CALL authentication method providing just the JWT token
                    Authentication authentication = authenticateJWTToken(jwtToken);
                    if (authentication != null) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    } else {
                        log.debug("JWT token was ignored by the JWTProcessingFilter, processing other filters");
                        filterChain.doFilter(request, response);
                    }
                } else {
                    throw new BadCredentialsException("JWT authentication failed, header doesn't contain a JWT token.");
                }

            } else {
                log.debug("AbstractJWTProcessingFilter.doFilter url not in the filter pattern, JWT filter ignored"); 
                filterChain.doFilter(request, response);
            }
        } catch (Exception ex) {
            log.debug("Exception in JWT processing filter.", ex);
            throw new BadCredentialsException("JWT authentication threw an exception.", ex);
        }
    }

    public abstract Authentication authenticateJWTToken(String jwtToken);

}
