/*
 * MongoMutableAclServiceTests.java
 */
package com.cedac.security.acls.mongo;

import com.lordofthejars.nosqlunit.annotation.ShouldMatchDataSet;
import com.lordofthejars.nosqlunit.annotation.UsingDataSet;
import com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb;
import com.lordofthejars.nosqlunit.mongodb.MongoDbRule;
import com.mongodb.Mongo;

import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.cache.support.NoOpCacheManager;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SpringCacheBasedAclCache;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import static com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb.InMemoryMongoRuleBuilder.newInMemoryMongoDbRule;
import static com.lordofthejars.nosqlunit.mongodb.MongoDbRule.MongoDbRuleBuilder.newMongoDbRule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
@UsingDataSet
public class MongoMutableAclServiceTests {
    @ClassRule
    public static InMemoryMongoDb inMemoryMongoDb = newInMemoryMongoDbRule().targetPath("target/test-db").build();

    @Rule
    public MongoDbRule embeddedMongoDbRule = newMongoDbRule().defaultEmbeddedMongoDb("test");

    private MongoMutableAclService fixture;
    @Mock
    private PermissionGrantingStrategy pgs;
    @Mock
    private AclAuthorizationStrategy aas;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        Mongo mongo = embeddedMongoDbRule.getDatabaseOperation().connectionManager();
        final AclCache aclCache = new SpringCacheBasedAclCache(new NoOpCacheManager().getCache("acl"), pgs, aas);
        fixture = new MongoMutableAclService(mongo, "test", aclCache, pgs, aas);
        fixture.afterPropertiesSet();

        SecurityContextHolder.getContext()
                .setAuthentication(new PreAuthenticatedAuthenticationToken("admin@cedac.com", "password"));
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    @ShouldMatchDataSet
    public void creatingAcl_withNoAcl() {
        MutableAcl acl = fixture.createAcl(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "2"));

        assertNotNull(acl);
        assertEquals("com.cedac.smartresidence.profile.domain.Home", acl.getObjectIdentity().getType());
        assertEquals("2", acl.getObjectIdentity().getIdentifier());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getOwner());
        assertEquals(true, acl.isEntriesInheriting());
        assertEquals(0, acl.getEntries().size());
    }

    @Test
    @ShouldMatchDataSet
    public void updateAcl_changeOwner() {
        MutableAcl acl = (MutableAcl) fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));
        acl.setOwner(new PrincipalSid("other@cedac.com"));

        fixture.updateAcl(acl);
    }

    @Test
    @ShouldMatchDataSet
    public void updateAcl_changeEntriesInheriting() {
        MutableAcl acl = (MutableAcl) fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));
        acl.setEntriesInheriting(false);

        fixture.updateAcl(acl);
    }

    @Test
    @ShouldMatchDataSet
    public void updateAcl_changeParent() {
        MutableAcl acl = (MutableAcl) fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.2"));
        acl.setParent(
                fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.1")));

        fixture.updateAcl(acl);
    }

    @Test
    @ShouldMatchDataSet
    public void updateAcl_addEntries() {
        MutableAcl acl = (MutableAcl) fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.2"));
        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_USER"), true);
        acl.insertAce(1, BasePermission.WRITE, new GrantedAuthoritySid("ROLE_USER"), true);

        fixture.updateAcl(acl);
    }

    @Test
    @ShouldMatchDataSet
    public void updateAcl_updateEntries() {
        MutableAcl acl = (MutableAcl) fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));
        acl.updateAce(2, BasePermission.DELETE);

        fixture.updateAcl(acl);
    }

    @Test
    @ShouldMatchDataSet
    public void updateAcl_deleteEntries() {
        MutableAcl acl = (MutableAcl) fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));
        acl.deleteAce(5);

        fixture.updateAcl(acl);
    }

    @Test(expected = AlreadyExistsException.class)
    @ShouldMatchDataSet
    public void creatingAcl_withExistingAcl() {
        fixture.createAcl(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));
    }

    @Test
    @ShouldMatchDataSet
    public void deleteAcl_cascadeWithNoChildren() {
        fixture.deleteAcl(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.2"), true);
    }

    @Test
    @ShouldMatchDataSet
    public void deleteAcl_noCascadeWithNoChildren() {
        fixture.deleteAcl(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.2"), false);
    }

    @Test
    @ShouldMatchDataSet
    public void deleteAcl_cascadeWithChildren() {
        fixture.deleteAcl(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Room", "1.1"), true);
    }

    @Test(expected = ChildrenExistException.class)
    @ShouldMatchDataSet
    public void deleteAcl_noCascadeWithChildren() {
        fixture.deleteAcl(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Room", "1.1"), false);
    }
}
