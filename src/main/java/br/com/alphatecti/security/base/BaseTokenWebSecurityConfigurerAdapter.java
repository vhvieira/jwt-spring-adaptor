package br.com.alphatecti.security.base;

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

import com.github.benmanes.caffeine.cache.Caffeine;

import br.com.alphatecti.security.jwt.filter.JWTExternalAuthenticationFilter;
import br.com.alphatecti.security.jwt.filter.JWTInternalAuthenticationFilter;
import br.com.alphatecti.security.jwt.parser.JWTInternalTokenParser;
import br.com.alphatecti.security.jwt.parser.JWTTokenParser;

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
