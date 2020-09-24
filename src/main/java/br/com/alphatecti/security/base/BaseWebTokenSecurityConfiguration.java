package br.com.alphatecti.security.base;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BaseWebTokenSecurityConfiguration {
    
    /*
     * Configuration of web token
     */
    private String urlFilter;
    private String tokenSecret;
    private long expirationTimeInMiliseconds;
    private long cacheExpirationTime;

}
