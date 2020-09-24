package br.com.alphatecti.security.base.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
            httpSecurity.csrf().disable().exceptionHandling().authenticationEntryPoint(unauthorizedHandler()).and().sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests().antMatchers(configuration.getUrlFilter())
                    .permitAll().anyRequest().authenticated();

            httpSecurity.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
            httpSecurity.headers().cacheControl();
        }
    }

}
