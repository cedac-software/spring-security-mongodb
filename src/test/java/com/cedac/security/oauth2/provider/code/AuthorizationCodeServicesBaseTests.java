/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cedac.security.oauth2.provider.code;

import com.cedac.security.oauth2.provider.RequestTokenFactory;

import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * @author mauro.franceschini
 * @since 1.0.0
 */
public abstract class AuthorizationCodeServicesBaseTests {
    abstract AuthorizationCodeServices getAuthorizationCodeServices();

    @Test
    public void testCreateAuthorizationCode() {
        OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
                new TestAuthentication("test2", false));
        String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
        assertNotNull(code);

        OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
        assertEquals(expectedAuthentication, actualAuthentication);
    }

    @Test
    public void testConsumeRemovesCode() {
        OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
                new TestAuthentication("test2", false));
        String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
        assertNotNull(code);

        OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
        assertEquals(expectedAuthentication, actualAuthentication);

        try {
            getAuthorizationCodeServices().consumeAuthorizationCode(code);
            fail("Should have thrown exception");
        } catch (InvalidGrantException e) {
            // good we expected this
        }
    }

    @Test
    public void testConsumeNonExistingCode() {
        try {
            getAuthorizationCodeServices().consumeAuthorizationCode("doesnt exist");
            fail("Should have thrown exception");
        } catch (InvalidGrantException e) {
            // good we expected this
        }
    }

    protected static class TestAuthentication extends AbstractAuthenticationToken {

        private static final long serialVersionUID = 1L;

        private String principal;

        public TestAuthentication(String name, boolean authenticated) {
            super(null);
            setAuthenticated(authenticated);
            this.principal = name;
        }

        public Object getCredentials() {
            return null;
        }

        public Object getPrincipal() {
            return this.principal;
        }
    }
}
