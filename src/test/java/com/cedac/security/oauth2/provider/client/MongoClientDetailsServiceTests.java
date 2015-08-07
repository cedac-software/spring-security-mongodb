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
package com.cedac.security.oauth2.provider.client;

import com.lordofthejars.nosqlunit.annotation.UsingDataSet;
import com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb;
import com.lordofthejars.nosqlunit.mongodb.MongoDbRule;
import com.mongodb.BasicDBObject;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.Mongo;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;

import static com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb.InMemoryMongoRuleBuilder.newInMemoryMongoDbRule;
import static com.lordofthejars.nosqlunit.mongodb.MongoDbRule.MongoDbRuleBuilder.newMongoDbRule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author mauro.franceschini
 * @since 1.0.0
 */
@UsingDataSet
public class MongoClientDetailsServiceTests {
    @ClassRule
    public static InMemoryMongoDb inMemoryMongoDb = newInMemoryMongoDbRule().targetPath("target/test-db").build();

    @Rule
    public MongoDbRule embeddedMongoDbRule = newMongoDbRule().defaultEmbeddedMongoDb("client_details");

    private MongoClientDetailsService fixture;
    private DBCollection collection;

    @Before
    public void setUp() throws Exception {
        Mongo mongo = embeddedMongoDbRule.getDatabaseOperation().connectionManager();
        collection = mongo.getDB("client_details").getCollection("client_details");
        fixture = new MongoClientDetailsService(mongo, "client_details");
        fixture.afterPropertiesSet();
    }

    @Test(expected = NoSuchClientException.class)
    public void testLoadingClientForNonExistingClientId() {
        fixture.loadClientByClientId("nonExistingClientId");
    }

    @Test
    public void testLoadingClientIdWithNoDetails() {
        collection.insert(new BasicDBObject("clientId", "clientIdWithNoDetails"));

        ClientDetails clientDetails = fixture.loadClientByClientId("clientIdWithNoDetails");

        assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
        assertFalse(clientDetails.isSecretRequired());
        assertNull(clientDetails.getClientSecret());
        assertFalse(clientDetails.isScoped());
        assertEquals(0, clientDetails.getScope().size());
        assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
        assertNull(clientDetails.getRegisteredRedirectUri());
        assertEquals(0, clientDetails.getAuthorities().size());
        assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
        assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
    }

    @Test
    public void testLoadingClientIdWithAdditionalInformation() {
        collection.insert(new BasicDBObject("clientId", "clientIdWithAddInfo")
                .append("additionalInformation", new BasicDBObject("foo", "bar")));

        ClientDetails clientDetails = fixture.loadClientByClientId("clientIdWithAddInfo");

        assertEquals("clientIdWithAddInfo", clientDetails.getClientId());
        assertEquals(Collections.singletonMap("foo", "bar"), clientDetails.getAdditionalInformation());
    }

    @Test
    public void testLoadingClientIdWithSingleDetails() {
        collection.insert(new BasicDBObject("clientId", "clientIdWithSingleDetails").append("clientSecret", "mySecret")
                .append("resourceIds", Arrays.asList("myResource")).append("scope", Arrays.asList("myScope"))
                .append("authorizedGrantTypes", Arrays.asList("myAuthorizedGrantType"))
                .append("registeredRedirectUris", Arrays.asList("myRedirectUri"))
                .append("authorities", Arrays.asList("myAuthority")).append("accessTokenValidity", 100)
                .append("refreshTokenValidity", 200).append("autoapprove", "true"));

        ClientDetails clientDetails = fixture.loadClientByClientId("clientIdWithSingleDetails");

        assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(1, clientDetails.getScope().size());
        assertEquals("myScope", clientDetails.getScope().iterator().next());
        assertEquals(1, clientDetails.getResourceIds().size());
        assertEquals("myResource", clientDetails.getResourceIds().iterator().next());
        assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
        assertEquals("myAuthorizedGrantType", clientDetails.getAuthorizedGrantTypes().iterator().next());
        assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri().iterator().next());
        assertEquals(1, clientDetails.getAuthorities().size());
        assertEquals("myAuthority", clientDetails.getAuthorities().iterator().next().getAuthority());
        assertEquals(new Integer(100), clientDetails.getAccessTokenValiditySeconds());
        assertEquals(new Integer(200), clientDetails.getRefreshTokenValiditySeconds());
    }

    @Test
    public void testLoadingClientIdWithMultipleDetails() {
        collection
                .insert(new BasicDBObject("clientId", "clientIdWithMultipleDetails").append("clientSecret", "mySecret")
                        .append("resourceIds", Arrays.asList("myResource1", "myResource2"))
                        .append("scope", Arrays.asList("myScope1", "myScope2")).append("authorizedGrantTypes",
                                Arrays.asList("myAuthorizedGrantType1", "myAuthorizedGrantType2"))
                        .append("registeredRedirectUris", Arrays.asList("myRedirectUri1", "myRedirectUri2"))
                        .append("authorities", Arrays.asList("myAuthority1", "myAuthority2"))
                        .append("accessTokenValidity", 100).append("refreshTokenValidity", 200)
                        .append("autoapprove", Arrays.asList("read", "write")));

        ClientDetails clientDetails = fixture.loadClientByClientId("clientIdWithMultipleDetails");

        assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(2, clientDetails.getResourceIds().size());
        Iterator<String> resourceIds = clientDetails.getResourceIds().iterator();
        assertEquals("myResource1", resourceIds.next());
        assertEquals("myResource2", resourceIds.next());
        assertEquals(2, clientDetails.getScope().size());
        Iterator<String> scope = clientDetails.getScope().iterator();
        assertEquals("myScope1", scope.next());
        assertEquals("myScope2", scope.next());
        assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
        Iterator<String> grantTypes = clientDetails.getAuthorizedGrantTypes().iterator();
        assertEquals("myAuthorizedGrantType1", grantTypes.next());
        assertEquals("myAuthorizedGrantType2", grantTypes.next());
        assertEquals(2, clientDetails.getRegisteredRedirectUri().size());
        Iterator<String> redirectUris = clientDetails.getRegisteredRedirectUri().iterator();
        assertEquals("myRedirectUri1", redirectUris.next());
        assertEquals("myRedirectUri2", redirectUris.next());
        assertEquals(2, clientDetails.getAuthorities().size());
        Iterator<GrantedAuthority> authorities = clientDetails.getAuthorities().iterator();
        assertEquals("myAuthority1", authorities.next().getAuthority());
        assertEquals("myAuthority2", authorities.next().getAuthority());
        assertEquals(new Integer(100), clientDetails.getAccessTokenValiditySeconds());
        assertEquals(new Integer(200), clientDetails.getRefreshTokenValiditySeconds());
        assertTrue(clientDetails.isAutoApprove("read"));
    }

    @Test
    public void testAddClientWithNoDetails() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("addedClientIdWithNoDetails");

        fixture.addClientDetails(clientDetails);

        DBObject map = collection.findOne(new BasicDBObject("clientId", "addedClientIdWithNoDetails"));

        assertEquals("addedClientIdWithNoDetails", map.get("clientId"));
        assertFalse(map.containsField("clientSecret"));
    }

    @Test(expected = ClientAlreadyExistsException.class)
    public void testInsertDuplicateClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("duplicateClientIdWithNoDetails");

        fixture.addClientDetails(clientDetails);
        fixture.addClientDetails(clientDetails);
    }

    @Test
    public void testUpdateClientSecret() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        fixture.setPasswordEncoder(new PasswordEncoder() {

            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return true;
            }

            public String encode(CharSequence rawPassword) {
                return "BAR";
            }
        });
        fixture.addClientDetails(clientDetails);
        fixture.updateClientSecret(clientDetails.getClientId(), "foo");

        DBObject map = collection.findOne(new BasicDBObject("clientId", "newClientIdWithNoDetails"));

        assertEquals("newClientIdWithNoDetails", map.get("clientId"));
        assertTrue(map.containsField("clientSecret"));
        assertEquals("BAR", map.get("clientSecret"));
    }

    @Test
    public void testUpdateClientRedirectURI() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        fixture.addClientDetails(clientDetails);

        String[] redirectURI = { "http://localhost:8080", "http://localhost:9090" };
        clientDetails.setRegisteredRedirectUri(new HashSet<String>(Arrays.asList(redirectURI)));

        fixture.updateClientDetails(clientDetails);

        DBObject map = collection.findOne(new BasicDBObject("clientId", "newClientIdWithNoDetails"));

        assertEquals("newClientIdWithNoDetails", map.get("clientId"));
        assertTrue(map.containsField("registeredRedirectUris"));
        assertEquals(new HashSet<String>(Arrays.asList("http://localhost:8080", "http://localhost:9090")),
                map.get("registeredRedirectUris"));
    }

    @Test(expected = NoSuchClientException.class)
    public void testUpdateNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        fixture.updateClientDetails(clientDetails);
    }

    @Test
    public void testRemoveClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("deletedClientIdWithNoDetails");

        fixture.addClientDetails(clientDetails);
        fixture.removeClientDetails(clientDetails.getClientId());

        long count = collection.count(new BasicDBObject("clientId", "deletedClientIdWithNoDetails"));

        assertEquals(0, count);
    }

    @Test(expected = NoSuchClientException.class)
    public void testRemoveNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        fixture.removeClientDetails(clientDetails.getClientId());
    }

    @Test
    public void testFindClients() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("aclient");

        fixture.addClientDetails(clientDetails);
        int count = fixture.listClientDetails().size();

        assertEquals(1, count);
    }
}
