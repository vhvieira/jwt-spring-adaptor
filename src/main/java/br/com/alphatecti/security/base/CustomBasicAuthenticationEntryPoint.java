package br.com.alphatecti.security.base;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * An basic auth entry point that denies all requests by default
 * @author vhrodriguesv
 */
public class CustomBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

    ObjectMapper mapper = new ObjectMapper();

    @Override
    public void commence(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException authException) throws IOException {
        // Authentication failed, send error response.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.println(mapper.writeValueAsString("HTTP Status 401 : " + authException.getMessage()));
    }

    @Override
    public void afterPropertiesSet() {
        setRealmName("Realm");
    }
}
      