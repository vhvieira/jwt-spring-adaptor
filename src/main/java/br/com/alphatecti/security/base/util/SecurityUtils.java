package br.com.alphatecti.security.base.util;

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
