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

import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.avaya.ept.security.base.BaseTokenWebSecurityConfigurerAdapter;
import com.avaya.ept.security.jwt.filter.JWTExternalAuthenticationFilter;

/**
 * Configuration using Breeze JWT or external authentication Receives a token a try to access a private URL with that token.
 * 
 * --- Tech notes for testing --- Restricted page URL: https://cls1.ept.lab/services/UnifiedAgentController/workspaces/#/home
 * 
 * Login page: https://cls1.ept.lab:9443/services/AuthorizationService/UserLogin.jsp Login/Pass: t1a99@ept.lab / Avaya123
 * 
 * @author vhrodriguesv
 */
public abstract class BaseExternalJWTConfig extends BaseTokenWebSecurityConfigurerAdapter {

    /*
     * Configuration
     */
    private ExternalJWTConfiguration configuration;
    private static boolean wasInitilized = false;

    /**
     * Constructor with all required configuration
     */
    public BaseExternalJWTConfig(ExternalJWTConfiguration configuration) {
        super(configuration.toBaseWebTokenSecurityConfiguration());
        this.configuration = configuration;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        if (!wasInitilized) {
            wasInitilized = true;
            httpSecurity.csrf().disable().exceptionHandling().authenticationEntryPoint(unauthorizedHandler()).and().sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests().antMatchers(configuration.getUrlFilter())
                    .permitAll().anyRequest().authenticated();

            httpSecurity.addFilterBefore(externalAuthenticationFilterBean(), UsernamePasswordAuthenticationFilter.class);
            httpSecurity.headers().cacheControl();
        }
    }

    @Bean
    public Filter externalAuthenticationFilterBean() {
        return new JWTExternalAuthenticationFilter(configuration);
    }

}