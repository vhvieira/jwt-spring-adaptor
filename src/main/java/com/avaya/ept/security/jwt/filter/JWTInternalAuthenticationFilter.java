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

import static com.avaya.ept.security.jwt.util.HttpHeadersConstants.JWT_TOKEN_INTERNAL_TYPE;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.avaya.ept.security.base.config.InternalJWTConfiguration;
import com.avaya.ept.security.base.util.SecurityUtils;
import com.avaya.ept.security.jwt.parser.JWTTokenParser;

/**
 * Authenticates a token using an internal token
 * 
 * @author vhrodriguesv
 */
public class JWTInternalAuthenticationFilter extends AbstractJWTProcessingFilter {
    
    
    /*
     * Cache constant NAME
     */
    public static final String CACHE_NAME = "JWT_INTERNAL_CACHE";

    /*
     * Configuration for filter
     */
    private JWTTokenParser tokenParser;
    private InternalJWTConfiguration configuration;
    
    /*
     * Using this because @Cacheable(value = CACHE_NAME, key = "jwtToken") didn't work
     */
    @Autowired
    private CacheManager cacheManager;


    /**
     * Constructor with all required configuration
     */
    public JWTInternalAuthenticationFilter(InternalJWTConfiguration configuration, JWTTokenParser tokenParser) {
        super(configuration.getUrlFilter());
        this.configuration = configuration;
        this.tokenParser = tokenParser;
    }

    @Override
    public Authentication authenticateJWTToken(String jwtToken) {
        //validates it is internal token
        if (jwtToken.startsWith(JWT_TOKEN_INTERNAL_TYPE)) {
            //uses cache first
            if(cacheManager.getCache(CACHE_NAME).get(jwtToken) != null) {
                return (Authentication) cacheManager.getCache(CACHE_NAME).get(jwtToken).get();
            } else {
                String subject = tokenParser.parseJWTToken(jwtToken);
                if (subject != null) {
                    UsernamePasswordAuthenticationToken userAuthenticated = new UsernamePasswordAuthenticationToken(subject, null, SecurityUtils.getUpdatedAuthorites(configuration.getDefaultPermissions()));
                    cacheManager.getCache(CACHE_NAME).put(jwtToken, userAuthenticated);
                    return userAuthenticated;
                } else {
                    throw new BadCredentialsException("Internal token authentication failed. Token provided was invalid.");
                }
            }
         } else {
            //should be ignored, not internal token
            return null;
        }
    }

}
