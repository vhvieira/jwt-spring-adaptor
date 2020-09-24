/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.base.config;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;

import com.avaya.ept.security.base.BaseWebTokenSecurityConfiguration;

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
