/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.jwt.filter;

import org.springframework.security.core.Authentication;

/**
 * Interface for filtering class for JWT tokens
 * @author vhrodriguesv
 */
public interface JWTProcessingFilter {

    /**
     * Returns null in case should go the next filter
     * throws BadCredentialsException in case the authentication is invalid
     */
    public abstract Authentication authenticateJWTToken(String jwtToken);
}
