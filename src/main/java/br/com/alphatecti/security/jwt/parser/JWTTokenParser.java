package br.com.alphatecti.security.jwt.parser;

/**
 * Interface that represents JWT token parser
 * @author vhrodriguesv
 */
public interface JWTTokenParser {
    
    /**
     * Creates a new JWT Token
     */
    public String createJWTToken(String subject);
    
    /**
     * Parser a token using the given parameters
     * Return nulls in case of failure or invalid token
     */
    public String parseJWTToken(String token);

}
