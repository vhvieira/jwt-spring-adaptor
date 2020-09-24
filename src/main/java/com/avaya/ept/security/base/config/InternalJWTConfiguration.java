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

import com.avaya.ept.security.base.BaseWebTokenSecurityConfiguration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Configuration object for Internal JWT Token urlFilter, 
 * expirationTimeInMiliseconds and token tokenSecret are required
 * Default permissions can be empty
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InternalJWTConfiguration {
    
    private String urlFilter, tokenSecret;
    private long expirationTimeInMiliseconds;
    private long cacheExpirationTime;
    private List<String> defaultPermissions;

    public BaseWebTokenSecurityConfiguration toBaseWebTokenSecurityConfiguration() {
        return BaseWebTokenSecurityConfiguration.builder().urlFilter(urlFilter).tokenSecret(tokenSecret)
                .expirationTimeInMiliseconds(expirationTimeInMiliseconds).cacheExpirationTime(cacheExpirationTime).build();
    }
}
