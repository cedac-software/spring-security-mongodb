/*
 * MongoAclServiceTest.java
 */
package com.cedac.security.acls.mongo;

import com.lordofthejars.nosqlunit.annotation.ShouldMatchDataSet;
import com.lordofthejars.nosqlunit.annotation.UsingDataSet;
import com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb;
import com.lordofthejars.nosqlunit.mongodb.MongoDbRule;
import com.mongodb.Mongo;

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
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.lordofthejars.nosqlunit.mongodb.InMemoryMongoDb.InMemoryMongoRuleBuilder.newInMemoryMongoDbRule;
import static com.lordofthejars.nosqlunit.mongodb.MongoDbRule.MongoDbRuleBuilder.newMongoDbRule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

/**
 * Test cases for {@link MongoAclService} class.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
@UsingDataSet
@ShouldMatchDataSet
public class MongoAclServiceTests {
    @ClassRule
    public static InMemoryMongoDb inMemoryMongoDb = newInMemoryMongoDbRule().targetPath("target/test-db").build();

    @Rule
    public MongoDbRule embeddedMongoDbRule = newMongoDbRule().defaultEmbeddedMongoDb("test");

    private MongoAclService fixture;
    @Mock
    private PermissionGrantingStrategy pgs;
    @Mock
    private AclAuthorizationStrategy aas;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        Mongo mongo = embeddedMongoDbRule.getDatabaseOperation().connectionManager();
        final AclCache aclCache = new SpringCacheBasedAclCache(new NoOpCacheManager().getCache("acl"), pgs, aas);
        fixture = new MongoAclService(mongo, "test", aclCache, pgs, aas);
        fixture.afterPropertiesSet();
    }

    @Test(expected = NotFoundException.class)
    public void readAclById_shouldThrowNotFoundException() {
        fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "2"));
    }

    @Test(expected = NotFoundException.class)
    public void readAclById_withSid_shouldThrowNotFoundException() {
        List<Sid> sids = new ArrayList<Sid>();
        sids.add(new PrincipalSid("admin@cedac.com"));
        fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "2"), sids);
    }

    @Test
    public void readAclById_shouldLoadTheAcl() {
        Acl acl = fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));

        assertNotNull(acl);
        assertEquals("com.cedac.smartresidence.profile.domain.Home", acl.getObjectIdentity().getType());
        assertEquals("1", acl.getObjectIdentity().getIdentifier());
        assertNull(acl.getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getOwner());
        assertEquals(true, acl.isEntriesInheriting());
        assertEquals(6, acl.getEntries().size());

        assertEquals(0, acl.getEntries().get(0).getId());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMIN"), acl.getEntries().get(0).getSid());
        assertEquals(BasePermission.READ, acl.getEntries().get(0).getPermission());
        assertEquals(true, acl.getEntries().get(0).isGranting());
        assertSame(acl, acl.getEntries().get(0).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(0)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(0)).isAuditFailure());

        assertEquals(1, acl.getEntries().get(1).getId());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMIN"), acl.getEntries().get(1).getSid());
        assertEquals(BasePermission.WRITE, acl.getEntries().get(1).getPermission());
        assertEquals(true, acl.getEntries().get(1).isGranting());
        assertSame(acl, acl.getEntries().get(1).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(1)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(1)).isAuditFailure());

        assertEquals(2, acl.getEntries().get(2).getId());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMIN"), acl.getEntries().get(2).getSid());
        assertEquals(BasePermission.ADMINISTRATION, acl.getEntries().get(2).getPermission());
        assertEquals(true, acl.getEntries().get(2).isGranting());
        assertSame(acl, acl.getEntries().get(2).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(2)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(2)).isAuditFailure());

        assertEquals(3, acl.getEntries().get(3).getId());
        assertEquals(new PrincipalSid("mauro.franceschini@cedac.com"), acl.getEntries().get(3).getSid());
        assertEquals(BasePermission.READ, acl.getEntries().get(3).getPermission());
        assertEquals(true, acl.getEntries().get(3).isGranting());
        assertSame(acl, acl.getEntries().get(3).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(3)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(3)).isAuditFailure());

        assertEquals(4, acl.getEntries().get(4).getId());
        assertEquals(new PrincipalSid("mauro.franceschini@cedac.com"), acl.getEntries().get(4).getSid());
        assertEquals(BasePermission.WRITE, acl.getEntries().get(4).getPermission());
        assertEquals(true, acl.getEntries().get(4).isGranting());
        assertSame(acl, acl.getEntries().get(4).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(4)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(4)).isAuditFailure());

        assertEquals(5, acl.getEntries().get(5).getId());
        assertEquals(new PrincipalSid("other@cedac.com"), acl.getEntries().get(5).getSid());
        assertEquals(BasePermission.READ, acl.getEntries().get(5).getPermission());
        assertEquals(true, acl.getEntries().get(5).isGranting());
        assertSame(acl, acl.getEntries().get(5).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(5)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(5)).isAuditFailure());
    }

    @Test
    public void readAclById_withSid_shouldLoadTheAcl() {
        Acl acl = fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"),
                Arrays.asList(new GrantedAuthoritySid("ROLE_ADMIN"), new PrincipalSid("other@cedac.com")));

        assertNotNull(acl);
        assertEquals("com.cedac.smartresidence.profile.domain.Home", acl.getObjectIdentity().getType());
        assertEquals("1", acl.getObjectIdentity().getIdentifier());
        assertNull(acl.getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getOwner());
        assertEquals(true, acl.isEntriesInheriting());
        assertEquals(6, acl.getEntries().size());
        assertEquals(true, acl.isSidLoaded(
                Arrays.asList(new GrantedAuthoritySid("ROLE_ADMIN"), new PrincipalSid("other@cedac.com"))));

        assertEquals(0, acl.getEntries().get(0).getId());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMIN"), acl.getEntries().get(0).getSid());
        assertEquals(BasePermission.READ, acl.getEntries().get(0).getPermission());
        assertEquals(true, acl.getEntries().get(0).isGranting());
        assertSame(acl, acl.getEntries().get(0).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(0)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(0)).isAuditFailure());

        assertEquals(1, acl.getEntries().get(1).getId());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMIN"), acl.getEntries().get(1).getSid());
        assertEquals(BasePermission.WRITE, acl.getEntries().get(1).getPermission());
        assertEquals(true, acl.getEntries().get(1).isGranting());
        assertSame(acl, acl.getEntries().get(1).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(1)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(1)).isAuditFailure());

        assertEquals(2, acl.getEntries().get(2).getId());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMIN"), acl.getEntries().get(2).getSid());
        assertEquals(BasePermission.ADMINISTRATION, acl.getEntries().get(2).getPermission());
        assertEquals(true, acl.getEntries().get(2).isGranting());
        assertSame(acl, acl.getEntries().get(2).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(2)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(2)).isAuditFailure());

        assertEquals(3, acl.getEntries().get(3).getId());
        assertEquals(new PrincipalSid("mauro.franceschini@cedac.com"), acl.getEntries().get(3).getSid());
        assertEquals(BasePermission.READ, acl.getEntries().get(3).getPermission());
        assertEquals(true, acl.getEntries().get(3).isGranting());
        assertSame(acl, acl.getEntries().get(3).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(3)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(3)).isAuditFailure());

        assertEquals(4, acl.getEntries().get(4).getId());
        assertEquals(new PrincipalSid("mauro.franceschini@cedac.com"), acl.getEntries().get(4).getSid());
        assertEquals(BasePermission.WRITE, acl.getEntries().get(4).getPermission());
        assertEquals(true, acl.getEntries().get(4).isGranting());
        assertSame(acl, acl.getEntries().get(4).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(4)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(4)).isAuditFailure());

        assertEquals(5, acl.getEntries().get(5).getId());
        assertEquals(new PrincipalSid("other@cedac.com"), acl.getEntries().get(5).getSid());
        assertEquals(BasePermission.READ, acl.getEntries().get(5).getPermission());
        assertEquals(true, acl.getEntries().get(5).isGranting());
        assertSame(acl, acl.getEntries().get(5).getAcl());
        assertEquals(false, AuditableAccessControlEntry.class.cast(acl.getEntries().get(5)).isAuditSuccess());
        assertEquals(true, AuditableAccessControlEntry.class.cast(acl.getEntries().get(5)).isAuditFailure());
    }

    @Test
    public void readAclById_withParentAcl_shouldLoadTheAcls() {
        Acl acl = fixture.readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Room", "1.1"));

        assertNotNull(acl);
        assertEquals("com.cedac.smartresidence.profile.domain.Room", acl.getObjectIdentity().getType());
        assertEquals("1.1", acl.getObjectIdentity().getIdentifier());
        assertNotNull(acl.getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getOwner());
        assertEquals(true, acl.isEntriesInheriting());
        assertEquals(0, acl.getEntries().size());

        assertEquals("com.cedac.smartresidence.profile.domain.Home", acl.getParentAcl().getObjectIdentity().getType());
        assertEquals("1", acl.getParentAcl().getObjectIdentity().getIdentifier());
        assertNull(acl.getParentAcl().getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getParentAcl().getOwner());
        assertEquals(true, acl.getParentAcl().isEntriesInheriting());
        assertEquals(6, acl.getParentAcl().getEntries().size());
    }

    @Test
    public void readAclById_withDoubleParentAcl_shouldLoadTheAcls() {
        Acl acl = fixture
                .readAclById(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.1"));

        assertNotNull(acl);
        assertEquals("com.cedac.smartresidence.profile.domain.Device", acl.getObjectIdentity().getType());
        assertEquals("1.1.1", acl.getObjectIdentity().getIdentifier());
        assertNotNull(acl.getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getOwner());
        assertEquals(true, acl.isEntriesInheriting());
        assertEquals(0, acl.getEntries().size());

        assertEquals("com.cedac.smartresidence.profile.domain.Room", acl.getParentAcl().getObjectIdentity().getType());
        assertEquals("1.1", acl.getParentAcl().getObjectIdentity().getIdentifier());
        assertNotNull(acl.getParentAcl().getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getParentAcl().getOwner());
        assertEquals(true, acl.getParentAcl().isEntriesInheriting());
        assertEquals(0, acl.getParentAcl().getEntries().size());

        assertEquals("com.cedac.smartresidence.profile.domain.Home",
                acl.getParentAcl().getParentAcl().getObjectIdentity().getType());
        assertEquals("1", acl.getParentAcl().getParentAcl().getObjectIdentity().getIdentifier());
        assertNull(acl.getParentAcl().getParentAcl().getParentAcl());
        assertEquals(new PrincipalSid("admin@cedac.com"), acl.getParentAcl().getParentAcl().getOwner());
        assertEquals(true, acl.getParentAcl().getParentAcl().isEntriesInheriting());
        assertEquals(6, acl.getParentAcl().getParentAcl().getEntries().size());
    }

    @Test
    public void findChildren_withParentMissing() {
        List<ObjectIdentity> children = fixture
                .findChildren(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "2"));

        assertNull(children);
    }

    @Test
    public void findChildren_withNoChild() {
        List<ObjectIdentity> children = fixture
                .findChildren(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Device", "1.1.1"));

        assertNull(children);
    }

    @Test
    public void findChildren_withOneChild() {
        List<ObjectIdentity> children = fixture
                .findChildren(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Home", "1"));

        assertNotNull(children);
        assertEquals(1, children.size());
        assertEquals("com.cedac.smartresidence.profile.domain.Room", children.get(0).getType());
        assertEquals("1.1", children.get(0).getIdentifier());
    }

    @Test
    public void findChildren_withMoreChild() {
        List<ObjectIdentity> children = fixture
                .findChildren(new ObjectIdentityImpl("com.cedac.smartresidence.profile.domain.Room", "1.1"));

        assertNotNull(children);
        assertEquals(2, children.size());
        assertEquals("com.cedac.smartresidence.profile.domain.Device", children.get(0).getType());
        assertEquals("1.1.1", children.get(0).getIdentifier());
        assertEquals("com.cedac.smartresidence.profile.domain.Device", children.get(1).getType());
        assertEquals("1.1.2", children.get(1).getIdentifier());
    }
}
