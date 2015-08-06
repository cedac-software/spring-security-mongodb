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
package com.cedac.security.acls.mongo;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.util.FieldUtils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * ACL service for mongo db.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
public class MongoAclService implements AclService, InitializingBean {
    protected static final Marker ACL = MarkerFactory.getDetachedMarker("acl");
    private static final Logger LOG = LoggerFactory.getLogger(MongoAclService.class);

    private static final String DEFAULT_ACL_COLLECTION_NAME = "acl";
    private static final String DEFAULT_OBJECT_ID_FIELD_NAME = "objectId";
    private static final String DEFAULT_CLASS_FIELD_NAME = "class";
    private static final String DEFAULT_IDENTITY_FIELD_NAME = "identity";
    private static final String DEFAULT_PARENT_OBJECT_FIELD_NAME = "parent";
    private static final String DEFAULT_OWNER_FIELD_NAME = "owner";
    private static final String DEFAULT_PRINCIPAL_FIELD_NAME = "principal";
    private static final String DEFAULT_SID_FIELD_NAME = "sid";
    private static final String DEFAULT_ENTRIES_FIELD_NAME = "entries";
    private static final String DEFAULT_ENTRIES_INHERITING_FIELD_NAME = "entriesInheriting";
    private static final String DEFAULT_MASK_FIELD_NAME = "mask";
    private static final String DEFAULT_GRANTING_FIELD_NAME = "granting";
    private static final String DEFAULT_AUDIT_SUCCESS_FIELD_NAME = "auditSuccess";
    private static final String DEFAULT_AUDIT_FAILURE_FIELD_NAME = "auditFailure";

    private final Field acesField = FieldUtils.getField(AclImpl.class, "aces");

    protected final AclCache aclCache;
    private final PermissionGrantingStrategy permissionGrantingStrategy;
    private final AclAuthorizationStrategy aclAuthorizationStrategy;

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();
    private DB db;
    protected String aclCollectionName = DEFAULT_ACL_COLLECTION_NAME;
    protected String objectIdFieldName = DEFAULT_OBJECT_ID_FIELD_NAME;
    protected String classFieldName = DEFAULT_CLASS_FIELD_NAME;
    protected String identityFieldName = DEFAULT_IDENTITY_FIELD_NAME;
    protected String parentObjectFieldName = DEFAULT_PARENT_OBJECT_FIELD_NAME;
    protected String ownerFieldName = DEFAULT_OWNER_FIELD_NAME;
    protected String principalFieldName = DEFAULT_PRINCIPAL_FIELD_NAME;
    protected String sidFieldName = DEFAULT_SID_FIELD_NAME;
    protected String entriesFieldName = DEFAULT_ENTRIES_FIELD_NAME;
    protected String entriesInheritingFieldName = DEFAULT_ENTRIES_INHERITING_FIELD_NAME;
    protected String maskFieldName = DEFAULT_MASK_FIELD_NAME;
    protected String grantingFieldName = DEFAULT_GRANTING_FIELD_NAME;
    protected String auditSuccessFieldName = DEFAULT_AUDIT_SUCCESS_FIELD_NAME;
    protected String auditFailureFieldName = DEFAULT_AUDIT_FAILURE_FIELD_NAME;
    protected String qualifiedObjectIdClassFieldName;
    protected String qualifiedObjectIdIdentityFieldName;
    protected String qualifiedParentObjectClassFieldName;
    protected String qualifiedParentObjectIdentityFieldName;

    public MongoAclService(Mongo mongo, String databaseName, AclCache aclCache,
            PermissionGrantingStrategy permissionGrantingStrategy, AclAuthorizationStrategy aclAuthorizationStrategy) {
        this(mongo.getDB(databaseName), aclCache, permissionGrantingStrategy, aclAuthorizationStrategy);
    }

    public MongoAclService(DB db, AclCache aclCache, PermissionGrantingStrategy permissionGrantingStrategy,
            AclAuthorizationStrategy aclAuthorizationStrategy) {
        this.db = db;
        this.aclCache = aclCache;
        this.permissionGrantingStrategy = permissionGrantingStrategy;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.qualifiedObjectIdClassFieldName = this.objectIdFieldName + "." + this.classFieldName;
        this.qualifiedObjectIdIdentityFieldName = this.objectIdFieldName + "." + this.identityFieldName;
        this.qualifiedParentObjectClassFieldName = this.parentObjectFieldName + "." + this.classFieldName;
        this.qualifiedParentObjectIdentityFieldName = this.parentObjectFieldName + "." + this.identityFieldName;

        if (!this.db.collectionExists(aclCollectionName)) {
            LOG.debug(ACL, "Creating collection for name '{}'", aclCollectionName);

            DBCollection aclCollection = this.db.createCollection(aclCollectionName, new BasicDBObject());
            aclCollection.createIndex(
                    new BasicDBObject(qualifiedObjectIdClassFieldName, 1).append(qualifiedObjectIdIdentityFieldName, 1),
                    new BasicDBObject("unique", 1).append("name", "acl_objectId_ix").append("background", 1));
            aclCollection.createIndex(new BasicDBObject(qualifiedParentObjectClassFieldName, 1)
                            .append(qualifiedParentObjectIdentityFieldName, 1),
                    new BasicDBObject("name", "acl_parent_ix").append("background", 1));
        }

        this.acesField.setAccessible(true);
    }

    protected final DBCollection getAclCollection() {
        return this.db.getCollection(aclCollectionName);
    }

    @Override
    public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
        LOG.debug(ACL, "Looking for children of object identity {}", parentIdentity);

        DBObject query = queryByParentIdentity(parentIdentity);
        DBObject projection = new BasicDBObject(objectIdFieldName, true);
        DBCursor cursor = null;
        try {
            cursor = getAclCollection().find(query, projection);
            if (cursor.count() == 0) {
                LOG.debug(ACL, "No child object found for identity {}", parentIdentity);

                return null;
            }

            LOG.trace(ACL, "Streaming cursor in order to retrieve child object identities");

            List<ObjectIdentity> oids = new ArrayList<ObjectIdentity>();
            while (cursor.hasNext()) {
                oids.add(toObjectIdentity((DBObject) cursor.next().get(objectIdFieldName)));
            }
            return oids;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    @Override
    public Acl readAclById(ObjectIdentity object) throws NotFoundException {
        return readAclById(object, null);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
        LOG.trace(ACL, "Reading ACL for object identity {}", object);

        Acl acl = aclCache.getFromCache(object);
        if (acl != null && acl.isSidLoaded(sids)) {
            LOG.debug(ACL, "ACL for id {} found in cache: {}", object, acl);

            return acl;
        } else {
            LOG.trace(ACL, "No ACL found in cache for id {}: looking into backend.", object);

            DBObject result = getAclCollection().findOne(queryByObjectIdentity(object));
            if (result == null) {
                LOG.warn(ACL, "No ACL found for object identity {}", object);

                throw new NotFoundException("No ACL found for object identity " + object);
            }

            LOG.trace(ACL, "Trying to loading parent ACL if needed.");

            Acl parentAcl = null;
            DBObject parentDbo = (DBObject) result.get(parentObjectFieldName);
            if (parentDbo != null) {
                parentAcl = readAclById(toObjectIdentity(parentDbo));
            }

            LOG.trace(ACL, "Extracting loaded SIDs");

            List<DBObject> entries = (List<DBObject>) result.get(entriesFieldName);
            Set<Sid> loadedSids = new HashSet<Sid>();
            if (sids != null) {
                loadedSids.addAll(sids);
            }
            if (entries != null) {
                for (DBObject entry : entries) {
                    loadedSids.add(toSid((DBObject) entry.get(sidFieldName)));
                }
            }

            Sid owner = toSid((DBObject) result.get(ownerFieldName));

            AclImpl loadedAcl = new AclImpl(object, result.get("_id").toString(), aclAuthorizationStrategy,
                    permissionGrantingStrategy, parentAcl, new ArrayList<Sid>(loadedSids),
                    (Boolean) result.get(entriesInheritingFieldName), owner);
            if (entries != null) {
                List<AccessControlEntry> aces = new ArrayList<AccessControlEntry>();
                for (int i = 0; i < entries.size(); i++) {
                    aces.add(toAccessControlEntry(i, loadedAcl, entries.get(i)));
                }
                try {
                    acesField.set(loadedAcl, new ArrayList<AccessControlEntry>(aces));
                } catch (Exception ex) {
                    throw new IllegalStateException("Unable to set ACEs.", ex);
                }
            }
            aclCache.putInCache(loadedAcl);
            return loadedAcl;
        }
    }

    @Override
    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException {
        return readAclsById(objects, null);
    }

    @Override
    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids)
            throws NotFoundException {
        Map<ObjectIdentity, Acl> result = new HashMap<ObjectIdentity, Acl>();
        for (ObjectIdentity oid : objects) {
            result.put(oid, readAclById(oid, sids));
        }

        // Check every requested object identity was found (throw NotFoundException if needed)
        for (ObjectIdentity oid : objects) {
            if (!result.containsKey(oid)) {
                throw new NotFoundException("Unable to find ACL information for object identity '" + oid + "'");
            }
        }

        return result;
    }

    protected final AccessControlEntry toAccessControlEntry(int id, Acl acl, DBObject dbo) {
        Sid sid = toSid((DBObject) dbo.get(sidFieldName));
        Permission permission = permissionFactory.buildFromMask(Number.class.cast(dbo.get(maskFieldName)).intValue());
        boolean granting = (Boolean) dbo.get(grantingFieldName);
        boolean auditSuccess = Optional.ofNullable((Boolean) dbo.get(auditSuccessFieldName)).orElse(Boolean.FALSE);
        boolean auditFailure = Optional.ofNullable((Boolean) dbo.get(auditFailureFieldName)).orElse(Boolean.FALSE);
        return new AccessControlEntryImpl(id, acl, sid, permission, granting, auditSuccess, auditFailure);
    }

    protected final Sid toSid(DBObject dbo) {
        final boolean principal = (Boolean) dbo.get(principalFieldName);
        final String sid = (String) dbo.get(sidFieldName);
        if (principal) {
            return new PrincipalSid(sid);
        } else {
            return new GrantedAuthoritySid(sid);
        }
    }

    protected final ObjectIdentity toObjectIdentity(DBObject dbo) {
        final String type = dbo.get(classFieldName).toString();
        final String identity = dbo.get(identityFieldName).toString();
        return new ObjectIdentityImpl(type, identity);
    }

    protected final DBObject queryById(Object id) {
        return new BasicDBObject("_id", id.toString());
    }

    protected final DBObject queryByParentIdentity(ObjectIdentity oid) {
        return new BasicDBObject(qualifiedParentObjectClassFieldName, oid.getType())
                .append(qualifiedParentObjectIdentityFieldName, oid.getIdentifier().toString());
    }

    protected final DBObject queryByObjectIdentity(ObjectIdentity oid) {
        return new BasicDBObject(qualifiedObjectIdClassFieldName, oid.getType())
                .append(qualifiedObjectIdIdentityFieldName, oid.getIdentifier().toString());
    }

    /*
     * Generic configuration setter.
     */

    public void setAclCollectionName(String aclCollectionName) {
        this.aclCollectionName = aclCollectionName;
    }

    public void setObjectIdFieldName(String objectIdFieldName) {
        this.objectIdFieldName = objectIdFieldName;
    }

    public void setClassFieldName(String classFieldName) {
        this.classFieldName = classFieldName;
    }

    public void setIdentityFieldName(String identityFieldName) {
        this.identityFieldName = identityFieldName;
    }

    public void setParentObjectFieldName(String parentObjectFieldName) {
        this.parentObjectFieldName = parentObjectFieldName;
    }

    public void setOwnerFieldName(String ownerFieldName) {
        this.ownerFieldName = ownerFieldName;
    }

    public void setPrincipalFieldName(String principalFieldName) {
        this.principalFieldName = principalFieldName;
    }

    public void setSidFieldName(String sidFieldName) {
        this.sidFieldName = sidFieldName;
    }

    public void setEntriesFieldName(String entriesFieldName) {
        this.entriesFieldName = entriesFieldName;
    }

    public void setEntriesInheritingFieldName(String entriesInheritingFieldName) {
        this.entriesInheritingFieldName = entriesInheritingFieldName;
    }

    public void setMaskFieldName(String maskFieldName) {
        this.maskFieldName = maskFieldName;
    }

    public void setGrantingFieldName(String grantingFieldName) {
        this.grantingFieldName = grantingFieldName;
    }

    public void setAuditSuccessFieldName(String auditSuccessFieldName) {
        this.auditSuccessFieldName = auditSuccessFieldName;
    }

    public void setAuditFailureFieldName(String auditFailureFieldName) {
        this.auditFailureFieldName = auditFailureFieldName;
    }

    public void setPermissionFactory(PermissionFactory permissionFactory) {
        this.permissionFactory = permissionFactory;
    }
}
