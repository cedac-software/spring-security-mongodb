/*
 * RequestTokenFactory.java
 */
package com.cedac.security.oauth2.provider;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author mauro.franceschini
 * @since 1.0.0
 */
public class RequestTokenFactory {
    public static OAuth2Request createOAuth2Request(Map<String, String> requestParameters, String clientId,
            Collection<? extends GrantedAuthority> authorities, boolean approved, Collection<String> scope,
            Set<String> resourceIds, String redirectUri, Set<String> responseTypes,
            Map<String, Serializable> extensionProperties) {
        return new OAuth2Request(requestParameters, clientId, authorities, approved,
                scope == null ? null : new LinkedHashSet<String>(scope), resourceIds, redirectUri, responseTypes,
                extensionProperties);
    }

    public static OAuth2Request createOAuth2Request(String clientId, boolean approved) {
        return createOAuth2Request(clientId, approved, null);
    }

    public static OAuth2Request createOAuth2Request(String clientId, boolean approved, Collection<String> scope) {
        return createOAuth2Request(Collections.<String, String>emptyMap(), clientId, approved, scope);
    }

    public static OAuth2Request createOAuth2Request(Map<String, String> parameters, String clientId, boolean approved,
            Collection<String> scope) {
        return createOAuth2Request(parameters, clientId, null, approved, scope, null, null, null, null);
    }
}
