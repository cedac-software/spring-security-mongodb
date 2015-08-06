/*
 * MongoAuthorizationCodeServices.java
 */
package com.cedac.security.oauth2.provider.code;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.WriteConcern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
import org.springframework.util.Assert;

/**
 * MongoOperations implementation of {@link AuthorizationCodeServices}.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
public class MongoAuthorizationCodeServices extends RandomValueAuthorizationCodeServices implements InitializingBean {
    private static final Marker CODE = MarkerFactory.getDetachedMarker("auth-code");
    private static final Logger LOG = LoggerFactory.getLogger(MongoAuthorizationCodeServices.class);

    private static final WriteConcern DEFAULT_WRITE_CONCERN = WriteConcern.NORMAL;

    private static final String DEFAULT_AUTH_CODE_COLLECTION_NAME = "auth_codes";

    private static final String DEFAULT_CODE_FIELD_NAME = "code";
    private static final String DEFAULT_AUTHENTICATION_FIELD_NAME = "authentication";

    private final DB db;

    private String authCodeCollectionName = DEFAULT_AUTH_CODE_COLLECTION_NAME;

    private String codeFieldName = DEFAULT_CODE_FIELD_NAME;
    private String authenticationFieldName = DEFAULT_AUTHENTICATION_FIELD_NAME;

    private WriteConcern writeConcern = DEFAULT_WRITE_CONCERN;

    public MongoAuthorizationCodeServices(Mongo mongo, String databaseName) {
        this(mongo.getDB(databaseName));
    }

    public MongoAuthorizationCodeServices(DB db) {
        Assert.notNull(db, "DB is required");
        this.db = db;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (!this.db.collectionExists(authCodeCollectionName)) {
            LOG.trace(CODE, "Creating {} collection", authCodeCollectionName);

            DBCollection collection = this.db.createCollection(authCodeCollectionName, new BasicDBObject());
            collection.createIndex(new BasicDBObject(codeFieldName, 1),
                    new BasicDBObject("name", authCodeCollectionName + "_" + codeFieldName + "_ix")
                            .append("unique", true).append("background", 1));

            LOG.debug(CODE, "Collection {} successfully created and indexed", authCodeCollectionName);
        }
    }

    private final DBCollection getAuthCodeCollection() {
        return db.getCollection(authCodeCollectionName);
    }

    @Override
    protected void store(String code, OAuth2Authentication authentication) {
        BasicDBObject dbo = new BasicDBObject(codeFieldName, code)
                .append(authenticationFieldName, SerializationUtils.serialize(authentication));
        getAuthCodeCollection().insert(dbo);
    }

    public OAuth2Authentication remove(String code) {
        OAuth2Authentication authentication = null;

        DBObject query = new BasicDBObject(codeFieldName, code);
        DBObject authCode = getAuthCodeCollection().findOne(query);
        if (authCode != null) {
            authentication = SerializationUtils.deserialize((byte[]) authCode.get(authenticationFieldName));
            if (authentication != null) {
                getAuthCodeCollection().remove(authCode);
            }
        }

        return authentication;
    }

    /*
     * Configuration properties.
     */

    public void setAuthCodeCollectionName(String authCodeCollectionName) {
        this.authCodeCollectionName = authCodeCollectionName;
    }

    public void setCodeFieldName(String codeFieldName) {
        this.codeFieldName = codeFieldName;
    }

    public void setAuthenticationFieldName(String authenticationFieldName) {
        this.authenticationFieldName = authenticationFieldName;
    }

    public void setWriteConcern(WriteConcern writeConcern) {
        this.writeConcern = writeConcern;
    }
}
