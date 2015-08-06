/*
 * MongoTokenStoreTests.java
 */
package com.cedac.security.oauth2.provider.token.store;

import com.cedac.security.oauth2.provider.RequestTokenFactory;
import com.lordofthejars.nosqlunit.annotation.UsingDataSet;
import com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb;
import com.lordofthejars.nosqlunit.mongodb.MongoDbRule;
import com.mongodb.Mongo;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Collection;

import static com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb.InMemoryMongoRuleBuilder.newInMemoryMongoDbRule;
import static com.lordofthejars.nosqlunit.mongodb.MongoDbRule.MongoDbRuleBuilder.newMongoDbRule;
import static org.junit.Assert.assertEquals;

/**
 * Test cases for {@link MongoTokenStore} class.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
@UsingDataSet
public class MongoTokenStoreTests extends TokenStoreBaseTests {
    @ClassRule
    public static InMemoryMongoDb inMemoryMongoDb = newInMemoryMongoDbRule().targetPath("target/test-db").build();

    @Rule
    public MongoDbRule embeddedMongoDbRule = newMongoDbRule().defaultEmbeddedMongoDb("test");

    private MongoTokenStore fixture;

    @Before
    public void setUp() throws Exception {
        Mongo mongo = embeddedMongoDbRule.getDatabaseOperation().connectionManager();
        fixture = new MongoTokenStore(mongo, "test");
        fixture.afterPropertiesSet();
    }

    @Override
    public MongoTokenStore getTokenStore() {
        return fixture;
    }

    @Test
    public void testFindAccessTokensByUserName() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
                RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");

        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByUserName("test2");
        assertEquals(1, actualOAuth2AccessTokens.size());
    }
}
