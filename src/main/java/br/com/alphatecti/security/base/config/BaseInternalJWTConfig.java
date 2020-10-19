package br.com.alphatecti.security.base.config;

import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.filter.CorsFilter;

import br.com.alphatecti.security.base.BaseTokenWebSecurityConfigurerAdapter;
import br.com.alphatecti.security.jwt.filter.JWTInternalAuthenticationFilter;

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
            // filter to be used
            Filter filter = authenticationTokenFilterBean();
            httpSecurity.csrf().disable();
            httpSecurity.cors();
            // BLACKLIST config (allow access to all, unless a filter blocks it)
            httpSecurity.addFilterAfter(filter, CorsFilter.class).authorizeRequests().anyRequest().permitAll();
            // WHITELIST config (only allows access if authentication occurs) - Need to re-test with Widgets
            //httpSecurity.csrf().disable().exceptionHandling().authenticationEntryPoint(unauthorizedHandler()).and().sessionManagement()
            //        .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests().antMatchers(configuration.getUrlFilter())
            //        .permitAll().anyRequest().authenticated();
            //httpSecurity.addFilterBefore(filter, CorsFilter.class);
            //httpSecurity.headers().cacheControl();
        }
    }

}
