/*
 * MongoTokenStoreTests.java
 */
package com.cedac.security.oauth2.provider.code;

import com.cedac.security.oauth2.provider.token.store.MongoTokenStore;
import com.lordofthejars.nosqlunit.annotation.UsingDataSet;
import com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb;
import com.lordofthejars.nosqlunit.mongodb.MongoDbRule;
import com.mongodb.Mongo;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

import static com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb.InMemoryMongoRuleBuilder.newInMemoryMongoDbRule;
import static com.lordofthejars.nosqlunit.mongodb.MongoDbRule.MongoDbRuleBuilder.newMongoDbRule;

/**
 * Test cases for {@link MongoTokenStore} class.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
@UsingDataSet
public class MongoAuthorizationCodeServicesTests extends AuthorizationCodeServicesBaseTests {
    @ClassRule
    public static InMemoryMongoDb inMemoryMongoDb = newInMemoryMongoDbRule().targetPath("target/test-db").build();

    @Rule
    public MongoDbRule embeddedMongoDbRule = newMongoDbRule().defaultEmbeddedMongoDb("test");

    private MongoAuthorizationCodeServices fixture;

    @Before
    public void setUp() throws Exception {
        Mongo mongo = embeddedMongoDbRule.getDatabaseOperation().connectionManager();
        fixture = new MongoAuthorizationCodeServices(mongo, "test");
        fixture.afterPropertiesSet();
    }

    @Override
    AuthorizationCodeServices getAuthorizationCodeServices() {
        return fixture;
    }
}
