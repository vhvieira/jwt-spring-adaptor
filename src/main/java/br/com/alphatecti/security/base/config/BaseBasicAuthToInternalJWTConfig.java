package br.com.alphatecti.security.base.config;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.Filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.filter.CorsFilter;

import br.com.alphatecti.security.base.AccountCredentials;
import br.com.alphatecti.security.base.BaseTokenWebSecurityConfigurerAdapter;
import br.com.alphatecti.security.jwt.filter.BasicAuthToJWTAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;

/**
 * Base class for security configuration using BASIC Authentication
 * 
 * @author vhrodriguesv
 */
@Configuration
@Slf4j
public abstract class BaseBasicAuthToInternalJWTConfig extends BaseTokenWebSecurityConfigurerAdapter {

    private Set<br.com.alphatecti.security.base.AccountCredentials> inMemoryCredentials = new HashSet<AccountCredentials>();

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
            // filter to be used
            Filter filter = new BasicAuthToJWTAuthenticationFilter(urlPattern, authenticationManager(), tokenParser());
            // bridge configuration and CORS
            httpSecurity.csrf().disable();
            httpSecurity.cors();
            //BLACKLIST configuration: to allow all if filter doesn't deny
            httpSecurity.addFilterAfter(filter, CorsFilter.class).authorizeRequests().anyRequest().permitAll();
            //WHITELIST configuration (allow only if filter authenticate)
            //httpSecurity.httpBasic().and().authorizeRequests().antMatchers(urlPattern).authenticated()
            //.and().addFilterBefore(filter, CorsFilter.class);
            httpSecurity.headers().cacheControl();
        } catch (Exception ex) {
            log.error("ERROR Initilizaling BaseBasicAuthToInternalJWTConfig and BasicAuthToJWTAuthenticationFilter", ex);
            throw ex;
        }
    }

}
