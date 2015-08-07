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
package com.cedac.security.oauth2.provider.approval;

import com.cedac.security.oauth2.provider.token.store.MongoTokenStore;
import com.lordofthejars.nosqlunit.annotation.UsingDataSet;
import com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb;
import com.lordofthejars.nosqlunit.mongodb.MongoDbRule;
import com.mongodb.Mongo;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;

import java.util.Arrays;

import static com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb.InMemoryMongoRuleBuilder.newInMemoryMongoDbRule;
import static com.lordofthejars.nosqlunit.mongodb.MongoDbRule.MongoDbRuleBuilder.newMongoDbRule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test cases for {@link MongoTokenStore} class.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
@UsingDataSet
public class MongoApprovalStoreTests extends AbstractTestApprovalStore {
    @ClassRule
    public static InMemoryMongoDb inMemoryMongoDb = newInMemoryMongoDbRule().targetPath("target/test-db").build();

    @Rule
    public MongoDbRule embeddedMongoDbRule = newMongoDbRule().defaultEmbeddedMongoDb("test");

    private MongoApprovalStore fixture;

    @Before
    public void setUp() throws Exception {
        Mongo mongo = embeddedMongoDbRule.getDatabaseOperation().connectionManager();
        fixture = new MongoApprovalStore(mongo, "test");
        fixture.afterPropertiesSet();
    }

    @Override
    public ApprovalStore getApprovalStore() {
        return fixture;
    }

    @Test
    public void testRevokeByExpiry() {
        fixture.setHandleRevocationsAsExpiry(true);
        Approval approval1 = new Approval("user", "client", "read", 10000, Approval.ApprovalStatus.APPROVED);
        Approval approval2 = new Approval("user", "client", "write", 10000, Approval.ApprovalStatus.APPROVED);
        assertTrue(getApprovalStore().addApprovals(Arrays.<Approval>asList(approval1, approval2)));
        getApprovalStore().revokeApprovals(Arrays.asList(approval1));
        assertEquals(2, getApprovalStore().getApprovals("user", "client").size());
        /*assertEquals(new Integer(1), new JdbcTemplate(db)
                        .queryForObject("SELECT COUNT(*) from oauth_approvals where userId='user' AND expiresAt < ?",
                                Integer.class, new Date(System.currentTimeMillis() + 1000)));*/
    }
}
