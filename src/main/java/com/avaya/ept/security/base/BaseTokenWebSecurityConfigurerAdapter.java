/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.base;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import com.avaya.ept.security.jwt.filter.JWTExternalAuthenticationFilter;
import com.avaya.ept.security.jwt.filter.JWTInternalAuthenticationFilter;
import com.avaya.ept.security.jwt.parser.JWTInternalTokenParser;
import com.avaya.ept.security.jwt.parser.JWTTokenParser;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Base configuration class for WebSecurityConfigurer
 * Contains common methods and commons bean definitions
 * @author vhrodriguesv
 */
public abstract class BaseTokenWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    /*
     * Configuration per class
     */
    protected String urlFilter;
    
    /*
     * Configuration of web token (common)
     */
    protected static String tokenSecret;
    protected static long expirationTimeInMiliseconds;
    protected static long cacheExpirationTime;
    
    /**
     * Constructor
     */
    protected BaseTokenWebSecurityConfigurerAdapter(BaseWebTokenSecurityConfiguration baseConfiguration) {
        applyConfiguration(baseConfiguration);
    }

    @Bean
    @Primary
    public BasicAuthenticationEntryPoint unauthorizedHandler() {
        return new CustomBasicAuthenticationEntryPoint();
    }
    
    @Bean
    @Primary
    public JWTTokenParser tokenParser() {
        return new JWTInternalTokenParser(tokenSecret, expirationTimeInMiliseconds);
    }   
    
    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    /*
     * CACHE CONFIGURATION - FOR JWT AUTHENTICATIONS
     */
    
    @Bean
    public Caffeine caffeineConfig() {
        return Caffeine.newBuilder().expireAfterWrite(cacheExpirationTime, TimeUnit.MINUTES);
    }

    @Bean
    public CacheManager cacheManager(Caffeine caffeine) {
        CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCaffeine(caffeine);
        caffeineCacheManager.setCacheNames(
                Arrays.asList(new String[] { JWTInternalAuthenticationFilter.CACHE_NAME, JWTExternalAuthenticationFilter.CACHE_NAME }));
        return caffeineCacheManager;
    }
    
    
    /**
     * JWT token configuration is the same, so secret and cache time are shared
     */
    private void applyConfiguration(BaseWebTokenSecurityConfiguration newConfiguration) {
        //if null create
        if(tokenSecret == null) {
            tokenSecret = newConfiguration.getTokenSecret();
        }
        if(expirationTimeInMiliseconds == 0L) {
            expirationTimeInMiliseconds = newConfiguration.getExpirationTimeInMiliseconds();
        }
        if(cacheExpirationTime == 0L) {
            cacheExpirationTime = newConfiguration.getCacheExpirationTime();
        }
        //url filter is always new
        urlFilter = newConfiguration.getUrlFilter();      
    }


}
