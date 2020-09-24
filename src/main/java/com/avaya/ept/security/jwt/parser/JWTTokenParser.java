/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.jwt.parser;

/**
 * Interface that represents JWT token parser
 * @author vhrodriguesv
 */
public interface JWTTokenParser {
    
    /**
     * Creates a new JWT Token
     */
    public String createJWTToken(String subject);
    
    /**
     * Parser a token using the given parameters
     * Return nulls in case of failure or invalid token
     */
    public String parseJWTToken(String token);

}
