/*
 * MongoMutableAclService.java
 */
package com.cedac.security.acls.mongo;

import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.WriteConcern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import java.util.List;

/**
 * MongoDb backed MutableAclService implementation.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
public class MongoMutableAclService extends MongoAclService implements MutableAclService {
    private static final Logger LOG = LoggerFactory.getLogger(MongoMutableAclService.class);

    private static final WriteConcern DEFAULT_WRITE_CONCERN = WriteConcern.NORMAL;

    private WriteConcern writeConcern = DEFAULT_WRITE_CONCERN;

    public MongoMutableAclService(Mongo mongo, String databaseName, AclCache aclCache,
            PermissionGrantingStrategy permissionGrantingStrategy, AclAuthorizationStrategy aclAuthorizationStrategy) {
        super(mongo, databaseName, aclCache, permissionGrantingStrategy, aclAuthorizationStrategy);
    }

    public MongoMutableAclService(DB db, AclCache aclCache, PermissionGrantingStrategy permissionGrantingStrategy,
            AclAuthorizationStrategy aclAuthorizationStrategy) {
        super(db, aclCache, permissionGrantingStrategy, aclAuthorizationStrategy);
    }

    @Override
    public MutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException {
        Assert.notNull(objectIdentity, "Object Identity required");

        LOG.trace(ACL, "Checking that object identity {} hasn't already been persisted", objectIdentity);

        DBObject result = getAclCollection().findOne(queryByObjectIdentity(objectIdentity));
        if (result != null) {
            LOG.warn(ACL, "An ACL entry for object identity {} already exists.", objectIdentity);

            throw new AlreadyExistsException("Object identity '" + objectIdentity + "' already exists");
        }

        LOG.trace(ACL, "Retrieving current principal in order to know who owns this ACL.");

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        PrincipalSid sid = new PrincipalSid(auth);

        LOG.debug(ACL, "Creating ACL entry.");

        DBObject ownerSid = new BasicDBObject(principalFieldName, true).append(sidFieldName, sid.getPrincipal());
        DBObject objectId = new BasicDBObject(classFieldName, objectIdentity.getType())
                .append(identityFieldName, objectIdentity.getIdentifier());
        DBObject acl = new BasicDBObject(ownerFieldName, ownerSid).append(objectIdFieldName, objectId)
                .append(entriesInheritingFieldName, true);
        getAclCollection().insert(acl, writeConcern);

        LOG.trace(ACL, "Retrieving back ACL using superclass.");

        return (MutableAcl) readAclById(objectIdentity);
    }

    @Override
    public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) throws ChildrenExistException {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(objectIdentity.getIdentifier(), "Object Identity doesn't provide an identifier");

        if (deleteChildren) {
            LOG.trace(ACL, "Recursively removing all the child acl entries.");

            List<ObjectIdentity> children = findChildren(objectIdentity);
            if (children != null) {
                for (ObjectIdentity child : children) {
                    deleteAcl(child, true);
                }
            }
        } else if (findChildren(objectIdentity) != null) {
            LOG.warn(ACL, "Children exists for object identity {}.", objectIdentity);

            throw new ChildrenExistException("Children exists for object identity " + objectIdentity);
        }

        LOG.debug(ACL, "Removing object identity {} from acl", objectIdentity);

        getAclCollection().remove(queryByObjectIdentity(objectIdentity), writeConcern);

        LOG.trace(ACL, "Evict the object identity {} from cache", objectIdentity);

        aclCache.evictFromCache(objectIdentity);
    }

    @Override
    public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
        Assert.notNull(acl.getId(), "Object Identity doesn't provide an identifier");

        DBObject persistedAcl = getAclCollection().findOne(queryByObjectIdentity(acl.getObjectIdentity()));

        if (persistedAcl == null) {
            LOG.trace(ACL, "No ACL found for object identity {}", acl.getObjectIdentity());

            throw new NotFoundException("No acl found for object identity " + acl.getObjectIdentity());
        }

        LOG.debug(ACL, "Updating persisted ACL object");

        if (acl.getParentAcl() != null) {
            ObjectIdentity parentOid = acl.getParentAcl().getObjectIdentity();
            persistedAcl.put(parentObjectFieldName, toDBObject(parentOid));
        }

        persistedAcl.put(ownerFieldName, toDBObject(acl.getOwner()));
        persistedAcl.put(entriesInheritingFieldName, acl.isEntriesInheriting());

        BasicDBList list = new BasicDBList();
        for (AccessControlEntry entry : acl.getEntries()) {
            list.add(toDBObject(entry));
        }
        persistedAcl.put(entriesFieldName, list);

        getAclCollection().save(persistedAcl, writeConcern);

        LOG.trace(ACL, "Clearing cache including children for object identity {}", acl.getObjectIdentity());

        clearCacheIncludingChildren(acl.getObjectIdentity());

        LOG.trace(ACL, "Retrieve ACL via superclass.");

        return (MutableAcl) super.readAclById(acl.getObjectIdentity());
    }

    private void clearCacheIncludingChildren(ObjectIdentity objectIdentity) {
        List<ObjectIdentity> children = findChildren(objectIdentity);
        if (children != null) {
            for (ObjectIdentity child : children) {
                clearCacheIncludingChildren(child);
            }
        }
        aclCache.evictFromCache(objectIdentity);
    }

    protected DBObject toDBObject(AccessControlEntry entry) {
        BasicDBObject dbo = new BasicDBObject();
        dbo.put(sidFieldName, toDBObject(entry.getSid()));
        dbo.put(maskFieldName, entry.getPermission().getMask());
        dbo.put(grantingFieldName, entry.isGranting());
        if (entry instanceof AuditableAccessControlEntry) {
            AuditableAccessControlEntry ace = (AuditableAccessControlEntry) entry;
            dbo.put(auditSuccessFieldName, ace.isAuditSuccess());
            dbo.put(auditFailureFieldName, ace.isAuditFailure());
        }
        return dbo;
    }

    protected DBObject toDBObject(ObjectIdentity oid) {
        return new BasicDBObject(classFieldName, oid.getType()).append(identityFieldName, oid.getIdentifier());
    }

    protected DBObject toDBObject(Sid sid) {
        DBObject object = null;
        if (sid != null) {
            if (sid instanceof PrincipalSid) {
                object = new BasicDBObject(principalFieldName, true)
                        .append(sidFieldName, PrincipalSid.class.cast(sid).getPrincipal());
            } else if (sid instanceof GrantedAuthoritySid) {
                object = new BasicDBObject(principalFieldName, false)
                        .append(sidFieldName, GrantedAuthoritySid.class.cast(sid).getGrantedAuthority());
            }
        }
        return object;
    }

    public void setWriteConcern(WriteConcern writeConcern) {
        this.writeConcern = writeConcern;
    }
}
