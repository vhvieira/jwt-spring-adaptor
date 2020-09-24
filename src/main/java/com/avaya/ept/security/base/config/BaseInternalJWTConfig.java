/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.base.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.avaya.ept.security.base.BaseTokenWebSecurityConfigurerAdapter;
import com.avaya.ept.security.jwt.filter.JWTInternalAuthenticationFilter;

/**
 * Base class for security configuration using internal JWT
 * 
 * @author vhrodriguesv
 */
public abstract class BaseInternalJWTConfig extends BaseTokenWebSecurityConfigurerAdapter {

    /*
     * Configuration
     */
    private InternalJWTConfiguration configuration;
    private static boolean wasInitilized = false;

    public BaseInternalJWTConfig(InternalJWTConfiguration configuration) {
        super(configuration.toBaseWebTokenSecurityConfiguration());
        this.configuration = configuration;
    }

    @Bean
    @Primary
    public JWTInternalAuthenticationFilter authenticationTokenFilterBean() {
        return new JWTInternalAuthenticationFilter(configuration, tokenParser());
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        if (!wasInitilized) {
            wasInitilized = true;
            httpSecurity.csrf().disable().exceptionHandling().authenticationEntryPoint(unauthorizedHandler()).and().sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests().antMatchers(configuration.getUrlFilter())
                    .permitAll().anyRequest().authenticated();

            httpSecurity.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
            httpSecurity.headers().cacheControl();
        }
    }

}
