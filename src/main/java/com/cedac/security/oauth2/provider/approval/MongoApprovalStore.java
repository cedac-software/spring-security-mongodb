/*
 * MongoApprovalStore.java
 */
package com.cedac.security.oauth2.provider.approval;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.WriteConcern;
import com.mongodb.WriteResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Mongo operations approval store.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
public class MongoApprovalStore implements ApprovalStore, InitializingBean {
    private static final Marker APPROVAL = MarkerFactory.getDetachedMarker("approval");
    private static final Logger LOG = LoggerFactory.getLogger(MongoApprovalStore.class);

    private static final WriteConcern DEFAULT_WRITE_CONCERN = WriteConcern.NORMAL;

    private static final String DEFAULT_APPROVALS_COLLECTION_NAME = "approvals";

    private static final String DEFAULT_USER_ID_FIELD_NAME = "userId";
    private static final String DEFAULT_CLIENT_ID_FIELD_NAME = "clientId";
    private static final String DEFAULT_SCOPE_FIELD_NAME = "scope";
    private static final String DEFAULT_STATUS_FIELD_NAME = "status";
    private static final String DEFAULT_EXPIRES_AT_FIELD_NAME = "expiresAt";
    private static final String DEFAULT_LAST_MODIFIED_AT_FIELD_NAME = "lastModifiedAt";

    private final DB db;

    private String approvalsCollectionName = DEFAULT_APPROVALS_COLLECTION_NAME;

    private String userIdFieldName = DEFAULT_USER_ID_FIELD_NAME;
    private String clientIdFieldName = DEFAULT_CLIENT_ID_FIELD_NAME;
    private String scopeFieldName = DEFAULT_SCOPE_FIELD_NAME;
    private String statusFieldName = DEFAULT_STATUS_FIELD_NAME;
    private String expiresAtFieldName = DEFAULT_EXPIRES_AT_FIELD_NAME;
    private String lastModifiedAtFieldName = DEFAULT_LAST_MODIFIED_AT_FIELD_NAME;

    private WriteConcern writeConcern = DEFAULT_WRITE_CONCERN;

    private boolean handleRevocationsAsExpiry = false;

    public MongoApprovalStore(Mongo mongo, String databaseName) {
        this(mongo.getDB(databaseName));
    }

    public MongoApprovalStore(DB db) {
        Assert.notNull(db, "DB is required");
        this.db = db;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (!this.db.collectionExists(approvalsCollectionName)) {
            LOG.trace(APPROVAL, "Creating {} collection", approvalsCollectionName);

            DBCollection collection = this.db.createCollection(approvalsCollectionName, new BasicDBObject());
            collection.createIndex(new BasicDBObject(clientIdFieldName, 1).append(userIdFieldName, 1),
                    new BasicDBObject("name",
                            approvalsCollectionName + "_" + clientIdFieldName + "_" + userIdFieldName + "_ix")
                            .append("background", 1));

            LOG.debug(APPROVAL, "Collection {} successfully created and indexed", approvalsCollectionName);
        }
    }

    private DBCollection getApprovalsCollection() {
        return db.getCollection(approvalsCollectionName);
    }

    @Override
    public boolean addApprovals(final Collection<Approval> approvals) {
        LOG.debug(APPROVAL, "Adding approvals: {}", approvals);

        boolean success = true;
        for (Approval approval : approvals) {
            DBObject query = new BasicDBObject(userIdFieldName, approval.getUserId())
                    .append(clientIdFieldName, approval.getClientId()).append(scopeFieldName, approval.getScope());
            DBObject obj = getApprovalsCollection().findOne(query);
            if (obj == null) {
                obj = new BasicDBObject(userIdFieldName, approval.getUserId())
                        .append(clientIdFieldName, approval.getClientId()).append(scopeFieldName, approval.getScope());
            }
            obj.put(statusFieldName, approval.getStatus().name());
            obj.put(expiresAtFieldName, approval.getExpiresAt());
            obj.put(lastModifiedAtFieldName, approval.getLastUpdatedAt());

            LOG.trace(APPROVAL, "Saving approval {}", obj);

            WriteResult result = getApprovalsCollection().save(obj, writeConcern);

            LOG.trace(APPROVAL, "Approval save result is {}", result);

            success = success && result.getN() == 1;
        }
        return success;
    }

    @Override
    public boolean revokeApprovals(Collection<Approval> approvals) {
        LOG.debug("Revoking approvals: {}", approvals);

        boolean success = true;
        for (Approval approval : approvals) {
            DBObject query = new BasicDBObject(userIdFieldName, approval.getUserId())
                    .append(clientIdFieldName, approval.getClientId()).append(scopeFieldName, approval.getScope());
            DBObject result = getApprovalsCollection().findOne(query);
            if (result != null) {
                WriteResult writeResult;
                if (handleRevocationsAsExpiry) {
                    LOG.trace(APPROVAL, "Handling revocation as expiry: updating approval {} field",
                            expiresAtFieldName);

                    result.put(expiresAtFieldName, new Date());
                    writeResult = getApprovalsCollection().save(result, writeConcern);
                } else {
                    LOG.trace(APPROVAL, "Handling revocation as delete: removing approval {}", result);

                    writeResult = getApprovalsCollection().remove(result, writeConcern);
                }
                success = success && writeResult.getN() == 1;
            } else {
                LOG.debug(APPROVAL, "No approval found for sample {}", query);
                success = false;
            }
        }
        return success;
    }

    public boolean purgeExpiredApprovals() {
        LOG.debug("Purging expired approvals from database");

        try {
            DBObject query = new BasicDBObject(expiresAtFieldName, new BasicDBObject("$lte", new Date()));
            WriteResult result = getApprovalsCollection().remove(query, writeConcern);

            LOG.debug(APPROVAL, "{} expired approvals deleted", result.getN());
        } catch (DataAccessException ex) {
            LOG.error(APPROVAL, "Error purging expired approvals", ex);

            return false;
        }
        return true;
    }

    @Override
    public List<Approval> getApprovals(String userName, String clientId) {
        BasicDBObject query = new BasicDBObject(userIdFieldName, userName).append(clientIdFieldName, clientId);
        DBCursor cursor = null;
        try {
            List<Approval> approvals = new ArrayList<Approval>();
            cursor = getApprovalsCollection().find(query);
            while (cursor.hasNext()) {
                DBObject dbo = cursor.next();
                approvals.add(new Approval((String) dbo.get(userIdFieldName), (String) dbo.get(clientIdFieldName),
                        (String) dbo.get(scopeFieldName), (Date) dbo.get(expiresAtFieldName),
                        Approval.ApprovalStatus.valueOf((String) dbo.get(statusFieldName)),
                        (Date) dbo.get(lastModifiedAtFieldName)));
            }
            return approvals;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    /*
     * Configuration properties.
     */

    public void setApprovalsCollectionName(String approvalsCollectionName) {
        this.approvalsCollectionName = approvalsCollectionName;
    }

    public void setUserIdFieldName(String userIdFieldName) {
        this.userIdFieldName = userIdFieldName;
    }

    public void setClientIdFieldName(String clientIdFieldName) {
        this.clientIdFieldName = clientIdFieldName;
    }

    public void setScopeFieldName(String scopeFieldName) {
        this.scopeFieldName = scopeFieldName;
    }

    public void setStatusFieldName(String statusFieldName) {
        this.statusFieldName = statusFieldName;
    }

    public void setExpiresAtFieldName(String expiresAtFieldName) {
        this.expiresAtFieldName = expiresAtFieldName;
    }

    public void setLastModifiedAtFiedlName(String lastModifiedAtFieldName) {
        this.lastModifiedAtFieldName = lastModifiedAtFieldName;
    }

    public void setWriteConcern(WriteConcern writeConcern) {
        this.writeConcern = writeConcern;
    }

    public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
        this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
    }
}
