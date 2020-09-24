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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.avaya.ept.security.base.AccountCredentials;
import com.avaya.ept.security.base.BaseTokenWebSecurityConfigurerAdapter;
import com.avaya.ept.security.jwt.filter.BasicAuthToJWTAuthenticationFilter;

import lombok.extern.slf4j.Slf4j;

/**
 * Base class for security configuration using BASIC Authentication
 * 
 * @author vhrodriguesv
 */
@Configuration
@Slf4j
public abstract class BaseBasicAuthToInternalJWTConfig extends BaseTokenWebSecurityConfigurerAdapter {

    private Set<AccountCredentials> inMemoryCredentials = new HashSet<AccountCredentials>();

    /*
     * Configuration
     */
    private List<AuthenticationProvider> authProviders;
    private LDAPConfiguration ldapConfiguration;
    private static boolean wasInitilized = false;

    public BaseBasicAuthToInternalJWTConfig(BasicAuthToInternalJWTConfiguration configuration) {
        super(configuration.toBaseWebTokenSecurityConfiguration());
        if (authProviders == null)
            this.authProviders = configuration.getCustomProviders();
        if (ldapConfiguration == null)
            this.ldapConfiguration = configuration.getLdapConfig();
    }

    public void addInMemoryCredentialsForTesting(AccountCredentials credentials) {
        inMemoryCredentials.add(credentials);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (!wasInitilized) {
            // initialize should run just once
            wasInitilized = true;
            // verify if should configure LDAP server
            if (ldapConfiguration != null) {
                auth.ldapAuthentication().userSearchFilter(ldapConfiguration.getUserSearchFilter())
                        .userDnPatterns(ldapConfiguration.getUserDnPatterns()).groupSearchBase(ldapConfiguration.getGroupSearchBase()).contextSource()
                        .url(ldapConfiguration.getUrl()).managerDn(ldapConfiguration.getManagerDn())
                        .managerPassword(ldapConfiguration.getManagerPassword()).and().passwordCompare().passwordEncoder(passwordEncoder())
                        .passwordAttribute(ldapConfiguration.getUserPasswordAttribute());
            }
            // if not LDAP then use auth provider and in memory
            for (AuthenticationProvider provider : authProviders)
                auth.authenticationProvider(provider);
            for (AccountCredentials credentials : this.inMemoryCredentials)
                auth.inMemoryAuthentication().withUser(credentials.getUsername()).password(credentials.getPassword()).roles(credentials.getRoles());
        }

    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        try {
            // transform in ant matcher by adding ** in the end
            String urlPattern = urlFilter + "**";
            httpSecurity.httpBasic().and().authorizeRequests().antMatchers(urlPattern).authenticated().and().addFilterBefore(
                    new BasicAuthToJWTAuthenticationFilter(urlPattern, authenticationManager(), tokenParser()),
                    UsernamePasswordAuthenticationFilter.class);
        } catch (Exception ex) {
            log.error("ERROR Initilizaling BaseBasicAuthToInternalJWTConfig and BasicAuthToJWTAuthenticationFilter", ex);
            throw ex;
        }
    }

}
