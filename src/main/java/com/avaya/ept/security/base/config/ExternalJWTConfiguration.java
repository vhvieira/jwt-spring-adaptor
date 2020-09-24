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
