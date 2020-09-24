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

import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import static com.avaya.ept.security.jwt.util.HttpHeadersConstants.*;

/**
 * Internal JWT Parser
 * 
 * @author vhrodriguesv
 */
@Slf4j
public class JWTInternalTokenParser implements JWTTokenParser {

    /*
     * Configuration for parser
     */
    private long expirationTimeInMiliseconds;
    private static SecretKey secretKey;
    private static final String ALGORITHM = "AES";

    public JWTInternalTokenParser(String tokenSecret, long expirationTimeInMiliseconds) {
        this.expirationTimeInMiliseconds = expirationTimeInMiliseconds;
        initializeSecretKey(tokenSecret);
    }

    @Override
    public String createJWTToken(String subject) {
        String jwtToken = Jwts.builder().setSubject(subject).setExpiration(new Date(System.currentTimeMillis() + expirationTimeInMiliseconds))
                .signWith(SignatureAlgorithm.HS512, secretKey).compact().trim();
        return JWT_TOKEN_INTERNAL_TYPE + jwtToken;
    }

    @Override
    public String parseJWTToken(String token) {
        try {
            String internalToken = token.substring(JWT_TOKEN_INTERNAL_TYPE.length());
            JwtParser jwtParser = Jwts.parser().setSigningKey(secretKey);
            if (jwtParser != null && token != null && jwtParser.parseClaimsJws(internalToken).getBody() != null) {
                return jwtParser.parseClaimsJws(internalToken).getBody().getSubject();
            } else {
                // non valid token (return null)
                return null;
            }
        } catch (Exception ex) {
            log.debug("Error parsing internal JWT, token provided was invalid or using a wrong key.", ex);
            return null;
        }
    }

    /**
     * JWT secret key has to be initialized in a static way to avoid exception:
     * io.jsonwebtoken.SignatureException: JWT signature does not match locally computed signature. 
     */
    private void initializeSecretKey(String myKey) {
        if (JWTInternalTokenParser.secretKey == null) {
            byte[] encodeKeyChar = myKey.getBytes();
            JWTInternalTokenParser.secretKey = new SecretKeySpec(encodeKeyChar, 0, myKey.length(), ALGORITHM);
        }
    }

}
