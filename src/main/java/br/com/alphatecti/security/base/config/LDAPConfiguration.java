package br.com.alphatecti.security.base.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LDAPConfiguration {
    
    private String userSearchFilter;
    private String groupSearchBase;
    private String userDnPatterns;
    private String userPasswordAttribute;
    private String url;
    private String managerDn;
    private String managerPassword;


}
