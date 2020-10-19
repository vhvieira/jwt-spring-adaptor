package br.com.alphatecti.security.jwt.filter;

import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.BASIC_SPLIT_STRING;
import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.BASIC_TOKEN_PREFIX;
import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.HEADER_STRING;
import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.JWT_TOKEN_PREFIX;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import br.com.alphatecti.security.base.AccountCredentials;
import br.com.alphatecti.security.jwt.parser.JWTTokenParser;

/**
 * Filter that reads basic authentication and converts and JWT internal token
 * 
 * @author vhrodriguesv
 */
public class BasicAuthToJWTAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    /**
     * Service
     */
    private JWTTokenParser tokenParser;

    public BasicAuthToJWTAuthenticationFilter(String url, AuthenticationManager authManager, JWTTokenParser tokenParser) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
        this.tokenParser = tokenParser;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String authorization = request.getHeader(HEADER_STRING);
        AccountCredentials credentials = retrieveCredentialsFromBasicAuthentication(authorization);

        return getAuthenticationManager()
                .authenticate(new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword(), Collections.emptyList()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Authentication auth)
            throws IOException, ServletException {
        response.addHeader(HEADER_STRING, JWT_TOKEN_PREFIX + " " + tokenParser.createJWTToken(auth.getName()));
        SecurityContextHolder.getContext().setAuthentication(auth);
        //continue chain to process request
        filterChain.doFilter(request, response);
    }

    private AccountCredentials retrieveCredentialsFromBasicAuthentication(String authorization) {
        if (authorization != null && authorization.startsWith(BASIC_TOKEN_PREFIX)) {
            // Authorization: Basic base64credentials
            String base64Credentials = authorization.substring(BASIC_TOKEN_PREFIX.length()).trim();
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded, StandardCharsets.UTF_8);
            // credentials = username:password
            final String[] values = credentials.split(BASIC_SPLIT_STRING, 2);
            AccountCredentials accountCredentials = new AccountCredentials();
            if (values.length > 1) {
                accountCredentials.setUsername(values[0]);
                accountCredentials.setPassword(values[1]);
            }
            return accountCredentials;
        } else {
            throw new BadCredentialsException("Basic credentials were not provided");
        }
    }

}