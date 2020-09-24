package br.com.alphatecti.security.base.config;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;

import br.com.alphatecti.security.base.BaseWebTokenSecurityConfiguration;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration object for Internal JWT Token
 * urlFilter, expirationTimeInMiliseconds and token tokenSecret are required
 * At least a custom provider should be informed to authenticate the user
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BasicAuthToInternalJWTConfiguration {
    private String urlFilter, tokenSecret;
    private long expirationInMiliseconds;
    List<AuthenticationProvider> customProviders;
    private LDAPConfiguration ldapConfig;

    public BaseWebTokenSecurityConfiguration toBaseWebTokenSecurityConfiguration() {
        return BaseWebTokenSecurityConfiguration.builder().urlFilter(urlFilter).tokenSecret(tokenSecret)
                .expirationTimeInMiliseconds(expirationInMiliseconds).build();
    }
}
