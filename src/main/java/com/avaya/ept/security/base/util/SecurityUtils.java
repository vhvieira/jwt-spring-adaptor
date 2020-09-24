/**
* Avaya Inc. - Proprietary (Restricted)
* Solely for authorized persons having a need to know pursuant to Company instructions.
*
* Copyright © Avaya Inc. All rights reserved.
*
* THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Avaya Inc.
* The copyright notice above does not evidence any actual or intended publication of such source code.
*/

package com.avaya.ept.security.base.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Class containing security related utility methods
 * @author vhrodriguesv
 */
public class SecurityUtils {

    /**
     * Method that adds the default authorities to the existing user authorities
     */
    public static Collection<? extends GrantedAuthority> getUpdatedAuthorites(List<String> newAuthorities) {
        Collection<SimpleGrantedAuthority> oldAuthorities = (Collection<SimpleGrantedAuthority>) SecurityContextHolder.getContext()
                .getAuthentication().getAuthorities();
        List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();

        for (String authorityName : newAuthorities) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(authorityName);
            updatedAuthorities.add(authority);
        }

        updatedAuthorities.addAll(oldAuthorities);
        return updatedAuthorities;
    }
}
