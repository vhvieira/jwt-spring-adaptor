package br.com.alphatecti.security.jwt.filter;

import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.JWT_TOKEN_INTERNAL_TYPE;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import br.com.alphatecti.security.base.config.InternalJWTConfiguration;
import br.com.alphatecti.security.base.util.SecurityUtils;
import br.com.alphatecti.security.jwt.parser.JWTTokenParser;
import lombok.extern.slf4j.Slf4j;

/**
 * Authenticates a token using an internal token
 * 
 * @author vhrodriguesv
 */
@Slf4j
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
            log.debug("Will validate using internal token: " + jwtToken);
            //uses cache first
            if(cacheManager.getCache(CACHE_NAME).get(jwtToken) != null) {
                return (Authentication) cacheManager.getCache(CACHE_NAME).get(jwtToken).get();
            } else {
                String subject = tokenParser.parseJWTToken(jwtToken);
                log.debug("Internal token subject: " + subject);
                if (subject != null) {
                    UsernamePasswordAuthenticationToken userAuthenticated = new UsernamePasswordAuthenticationToken(subject, null, SecurityUtils.getUpdatedAuthorites(configuration.getDefaultPermissions()));
                    cacheManager.getCache(CACHE_NAME).put(jwtToken, userAuthenticated);
                    return userAuthenticated;
                } else {
                    throw new BadCredentialsException("Internal token authentication failed. Token provided was invalid.");
                }
            }
         } else {
            log.debug("Not an internal token, ignoring it.");
            return null;
        }
    }

}
