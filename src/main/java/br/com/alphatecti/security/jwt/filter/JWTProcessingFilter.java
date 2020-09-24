package br.com.alphatecti.security.jwt.filter;

import org.springframework.security.core.Authentication;

/**
 * Interface for filtering class for JWT tokens
 * @author vhrodriguesv
 */
public interface JWTProcessingFilter {

    /**
     * Returns null in case should go the next filter
     * throws BadCredentialsException in case the authentication is invalid
     */
    public abstract Authentication authenticateJWTToken(String jwtToken);
}
