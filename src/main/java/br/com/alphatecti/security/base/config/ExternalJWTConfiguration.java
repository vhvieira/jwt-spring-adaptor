package br.com.alphatecti.security.base.config;

import java.util.List;

import br.com.alphatecti.security.base.BaseWebTokenSecurityConfiguration;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration object for External JWT Token urlFilter, externalURL and token subject 
 * are required proxy server and port are optional, as well default permission can be empty
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExternalJWTConfiguration {

    private String urlFilter, externalURL, tokenSubject, proxyServer;
    private int proxyPort;
    private long cacheExpirationTime;
    private List<String> defaultPermissions;

    public BaseWebTokenSecurityConfiguration toBaseWebTokenSecurityConfiguration() {
        return BaseWebTokenSecurityConfiguration.builder().urlFilter(urlFilter).cacheExpirationTime(cacheExpirationTime).build();
    }

}
