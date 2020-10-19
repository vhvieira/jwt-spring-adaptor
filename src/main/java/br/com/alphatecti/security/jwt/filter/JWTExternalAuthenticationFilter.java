package br.com.alphatecti.security.jwt.filter;

import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.HEADER_STRING;
import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.JWT_TOKEN_INTERNAL_TYPE;
import static br.com.alphatecti.security.jwt.util.HttpHeadersConstants.JWT_TOKEN_PREFIX;

import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.client.RestTemplate;

import br.com.alphatecti.security.base.config.ExternalJWTConfiguration;
import br.com.alphatecti.security.base.util.SecurityUtils;
import lombok.extern.slf4j.Slf4j;

/**
 * Authenticates a token using an external service
 * 
 * @author vhrodriguesv
 */
@Slf4j
public class JWTExternalAuthenticationFilter extends AbstractJWTProcessingFilter {

    /*
     * Cache constant NAME
     */
    public static final String CACHE_NAME = "JWT_EXTERNAL_CACHE";

    /*
     * Using this because @Cacheable(value = CACHE_NAME, key = "jwtToken") didn't work
     */
    @Autowired
    private CacheManager cacheManager;

    /*
     * Configuration for filter
     */
    private ExternalJWTConfiguration configuration;

    /**
     * Default constructor for external auth filter
     */
    public JWTExternalAuthenticationFilter(ExternalJWTConfiguration configuration) {
        super(configuration.getUrlFilter());
        this.configuration = configuration;
    }

    @Override
    public Authentication authenticateJWTToken(String jwtToken) {
        if (!jwtToken.startsWith(JWT_TOKEN_INTERNAL_TYPE)) {
            try {
                log.debug("Will validate using external token: " + jwtToken);
                if (cacheManager.getCache(CACHE_NAME).get(jwtToken) != null) {
                    log.debug("Using cache to validate external token");
                    return (Authentication) cacheManager.getCache(CACHE_NAME).get(jwtToken).get();
                } else {
                    ResponseEntity<String> externalResponse = callExternalURL(jwtToken, configuration.getExternalURL());
                    
                    //after follow all redirects it should be 200
                    if (externalResponse.getStatusCodeValue() != 200) {
                        // check if it was redirected to login page
                        throw new BadCredentialsException("External system authentication failed, external url didn't replied with HTTP200.");
                    }

                    // create an internal token based on configurations and stores on cache
                    UsernamePasswordAuthenticationToken userAuthenticated = new UsernamePasswordAuthenticationToken(configuration.getTokenSubject(),
                            null, SecurityUtils.getUpdatedAuthorites(configuration.getDefaultPermissions()));
                    cacheManager.getCache(CACHE_NAME).put(jwtToken, userAuthenticated);
                    
                    return userAuthenticated;
                }
            } catch (Exception ex) {
                log.debug("Error validating external JWT", ex);
                throw new BadCredentialsException("External system authentication failed", ex);
            }
        } else {
            // should be ignored, not external token
            log.debug("Not an external token, ignoring it.");
            return null;
        }
    }

    /**
     * Calls the external URL using the provided bearer token
     */
    private ResponseEntity<String> callExternalURL(String jwtToken, String url) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        RestTemplate restTemplate = getRestTemplate(configuration.getProxyServer(), configuration.getProxyPort());
        log.debug("RestTemplate created:  " + restTemplate);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HEADER_STRING, JWT_TOKEN_PREFIX + " " + jwtToken);
        HttpEntity<String> entity = new HttpEntity<String>("parameters", headers);
        log.debug("HttpHeaders created:  " + headers);
        ResponseEntity<String> externalResponse = restTemplate.exchange(url, HttpMethod.GET, entity,
                String.class);
        log.debug("Response code was:  " + externalResponse.getStatusCodeValue());
        return externalResponse;
    }

    /**
     * Get custom restTemplate with no redirects support and accepting any hosts in the certificate.
     */
    @Bean
    private RestTemplate getRestTemplate(String proxyHost, int proxyPort) {
        CloseableHttpClient httpClient;
        try {
            httpClient = getHttpClient(proxyHost, proxyPort);
            HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
            requestFactory.setHttpClient(httpClient);
            RestTemplate restTemplate = new RestTemplate(requestFactory);
            return restTemplate;
        } catch (Exception ex) {
            log.debug("Error initializing custom rest template on external JWT Auth", ex);
            throw new BadCredentialsException("External system authentication failed", ex);
        }
       
    }

    /**
     * Return the custom http client that has a self signed strategy and can support proxy + no redirects.
     * 
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     */
    private CloseableHttpClient getHttpClient(String proxyHost, int proxyPort)
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        TrustStrategy acceptingTrustStrategy = new TrustSelfSignedStrategy();
        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
        if (null != proxyHost && proxyPort > 0) {
            log.info("PROXY CONFIGURED | proxyHost=" + proxyHost + " | proxyPort=" + proxyPort);
            HttpHost proxy = new HttpHost(proxyHost, proxyPort, Proxy.Type.HTTP.name());
            return HttpClients.custom().setSSLSocketFactory(csf).setRoutePlanner(new DefaultProxyRoutePlanner(proxy)).disableRedirectHandling().build();
        }
        // create custom client
        return  HttpClients.custom().setSSLSocketFactory(csf).disableRedirectHandling().build();
    }

}