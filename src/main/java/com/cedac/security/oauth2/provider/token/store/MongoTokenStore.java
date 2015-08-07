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
package com.cedac.security.oauth2.provider.token.store;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.WriteConcern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Mongo operations token store.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
public class MongoTokenStore implements TokenStore, InitializingBean {
    private static final Marker TOKEN = MarkerFactory.getDetachedMarker("token");
    private static final Logger LOG = LoggerFactory.getLogger(MongoTokenStore.class);

    private static final WriteConcern DEFAULT_WRITE_CONCERN = WriteConcern.NORMAL;

    private static final String DEFAULT_ACCESS_TOKEN_COLLECTION_NAME = "access_tokens";
    private static final String DEFAULT_REFRESH_TOKEN_COLLECTION_NAME = "refresh_tokens";

    private static final String DEFAULT_TOKEN_ID_FIELD_NAME = "tokenId";
    private static final String DEFAULT_TOKEN_FIELD_NAME = "token";
    private static final String DEFAULT_AUTHENTICATION_ID_FIELD_NAME = "authenticationId";
    private static final String DEFAULT_USERNAME_FIELD_NAME = "username";
    private static final String DEFAULT_CLIENT_ID_FIELD_NAME = "clientId";
    private static final String DEFAULT_AUTHENTICATION_FIELD_NAME = "authentication";
    private static final String DEFAULT_REFRESH_TOKEN_FIELD_NAME = "refreshToken";

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    private final DB db;

    private String accessTokenCollectionName = DEFAULT_ACCESS_TOKEN_COLLECTION_NAME;
    private String refreshTokenCollectionName = DEFAULT_REFRESH_TOKEN_COLLECTION_NAME;

    private String tokenIdFieldName = DEFAULT_TOKEN_ID_FIELD_NAME;
    private String tokenFieldName = DEFAULT_TOKEN_FIELD_NAME;
    private String authenticationIdFieldName = DEFAULT_AUTHENTICATION_ID_FIELD_NAME;
    private String usernameFieldName = DEFAULT_USERNAME_FIELD_NAME;
    private String clientIdFieldName = DEFAULT_CLIENT_ID_FIELD_NAME;
    private String authenticationFieldName = DEFAULT_AUTHENTICATION_FIELD_NAME;
    private String refreshTokenFieldName = DEFAULT_REFRESH_TOKEN_FIELD_NAME;

    private WriteConcern writeConcern = DEFAULT_WRITE_CONCERN;

    public MongoTokenStore(Mongo mongo, String databaseName) {
        this(mongo.getDB(databaseName));
    }

    public MongoTokenStore(DB db) {
        Assert.notNull(db, "DB is required");
        this.db = db;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (!this.db.collectionExists(accessTokenCollectionName)) {
            LOG.trace(TOKEN, "Creating {} collection", accessTokenCollectionName);

            DBCollection collection = this.db.createCollection(accessTokenCollectionName, new BasicDBObject());
            collection.createIndex(new BasicDBObject(tokenIdFieldName, 1),
                    new BasicDBObject("name", accessTokenCollectionName + "_" + tokenIdFieldName + "_ix")
                            .append("background", 1));
            collection.createIndex(new BasicDBObject(authenticationIdFieldName, 1),
                    new BasicDBObject("name", accessTokenCollectionName + "_" + authenticationFieldName + "_ix")
                            .append("background", 1));

            LOG.debug(TOKEN, "Collection {} successfully created and indexed", accessTokenCollectionName);
        }
        if (!this.db.collectionExists(refreshTokenCollectionName)) {
            LOG.trace(TOKEN, "Creating {} collection", refreshTokenCollectionName);

            DBCollection collection = this.db.createCollection(refreshTokenCollectionName, new BasicDBObject());
            collection.createIndex(new BasicDBObject(tokenIdFieldName, 1),
                    new BasicDBObject("name", refreshTokenCollectionName + "_ix"));

            LOG.debug(TOKEN, "Collection {} successfully created and indexed", accessTokenCollectionName);
        }
    }

    private final DBCollection getAccessTokenCollection() {
        return db.getCollection(accessTokenCollectionName);
    }

    private final DBCollection getRefreshTokenCollection() {
        return db.getCollection(refreshTokenCollectionName);
    }

    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = null;

        String key = authenticationKeyGenerator.extractKey(authentication);
        try {
            DBObject query = new BasicDBObject(authenticationIdFieldName, key);
            DBObject projection = new BasicDBObject(tokenFieldName, 1);
            DBObject token = getAccessTokenCollection().findOne(query, projection);
            if (token != null) {
                accessToken = deserializeAccessToken((byte[]) token.get(tokenFieldName));
            } else {
                LOG.debug("Failed to find access token for authentication {}", authentication);
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Could not extract access token for authentication " + authentication, e);
        }

        if (accessToken != null && !key
                .equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
            removeAccessToken(accessToken.getValue());
            // Keep the store consistent (maybe the same user is represented by this authentication but the details have
            // changed)
            storeAccessToken(accessToken, authentication);
        }
        return accessToken;
    }

    public void storeAccessToken(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        String refreshToken = null;
        if (accessToken.getRefreshToken() != null) {
            refreshToken = accessToken.getRefreshToken().getValue();
        }

        if (readAccessToken(accessToken.getValue()) != null) {
            removeAccessToken(accessToken.getValue());
        }

        DBObject token = new BasicDBObject();
        token.put(tokenIdFieldName, extractTokenKey(accessToken.getValue()));
        token.put(tokenFieldName, serializeAccessToken(accessToken));
        token.put(authenticationIdFieldName, authenticationKeyGenerator.extractKey(authentication));
        if (!authentication.isClientOnly()) {
            token.put(usernameFieldName, authentication.getName());
        } else {
            token.put(usernameFieldName, null);
        }
        token.put(clientIdFieldName, authentication.getOAuth2Request().getClientId());
        token.put(authenticationFieldName, serializeAuthentication(authentication));
        token.put(refreshTokenFieldName, extractTokenKey(refreshToken));

        getAccessTokenCollection().insert(token, writeConcern);
    }

    public OAuth2AccessToken readAccessToken(String tokenValue) {
        OAuth2AccessToken accessToken = null;

        try {
            DBObject query = new BasicDBObject(tokenIdFieldName, extractTokenKey(tokenValue));
            DBObject projection = new BasicDBObject(tokenFieldName, 1);
            DBObject token = getAccessTokenCollection().findOne(query, projection);
            if (token != null) {
                accessToken = deserializeAccessToken((byte[]) token.get(tokenFieldName));
            } else {
                LOG.info("Failed to find access token for token {}", tokenValue);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize access token for " + tokenValue, e);

            removeAccessToken(tokenValue);
        }

        return accessToken;
    }

    public void removeAccessToken(OAuth2AccessToken token) {
        removeAccessToken(token.getValue());
    }

    public void removeAccessToken(String tokenValue) {
        DBObject query = new BasicDBObject(tokenIdFieldName, extractTokenKey(tokenValue));

        getAccessTokenCollection().remove(query, writeConcern);
    }

    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    public OAuth2Authentication readAuthentication(String token) {
        OAuth2Authentication authentication = null;

        try {
            DBObject query = new BasicDBObject(tokenIdFieldName, extractTokenKey(token));
            DBObject projection = new BasicDBObject(authenticationFieldName, 1);
            DBObject accessToken = getAccessTokenCollection().findOne(query, projection);
            if (accessToken != null) {
                authentication = deserializeAuthentication((byte[]) accessToken.get(authenticationFieldName));
            } else {
                LOG.info("Failed to find access token for token {}", token);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize authentication for " + token, e);

            removeAccessToken(token);
        }

        return authentication;
    }

    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        DBObject token = new BasicDBObject();
        token.put(tokenIdFieldName, extractTokenKey(refreshToken.getValue()));
        token.put(tokenFieldName, serializeRefreshToken(refreshToken));
        token.put(authenticationFieldName, serializeAuthentication(authentication));

        getRefreshTokenCollection().insert(token, writeConcern);
    }

    public OAuth2RefreshToken readRefreshToken(String token) {
        OAuth2RefreshToken refreshToken = null;

        try {
            DBObject query = new BasicDBObject(tokenIdFieldName, extractTokenKey(token));
            DBObject projection = new BasicDBObject(tokenFieldName, 1);
            DBObject savedToken = getRefreshTokenCollection().findOne(query, projection);
            if (savedToken != null) {
                refreshToken = deserializeRefreshToken((byte[]) savedToken.get(tokenFieldName));
            } else {
                LOG.info("Failed to find refresh token for token {}", token);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize refresh token for token " + token, e);

            removeRefreshToken(token);
        }

        return refreshToken;
    }

    public void removeRefreshToken(OAuth2RefreshToken token) {
        removeRefreshToken(token.getValue());
    }

    public void removeRefreshToken(String token) {
        DBObject query = new BasicDBObject(tokenIdFieldName, extractTokenKey(token));

        getRefreshTokenCollection().remove(query, writeConcern);
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        return readAuthenticationForRefreshToken(token.getValue());
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
        OAuth2Authentication authentication = null;

        try {
            DBObject query = new BasicDBObject(tokenIdFieldName, extractTokenKey(value));
            DBObject projection = new BasicDBObject(authenticationFieldName, 1);
            DBObject savedToken = getRefreshTokenCollection().findOne(query, projection);
            if (savedToken != null) {
                authentication = deserializeAuthentication((byte[]) savedToken.get(authenticationFieldName));
            } else {
                LOG.info("Failed to find access token for token {}", value);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize access token for " + value, e);

            removeRefreshToken(value);
        }

        return authentication;
    }

    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    public void removeAccessTokenUsingRefreshToken(String refreshToken) {
        DBObject query = new BasicDBObject(refreshTokenFieldName, extractTokenKey(refreshToken));

        getAccessTokenCollection().remove(query, writeConcern);
    }

    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        DBObject query = new BasicDBObject(clientIdFieldName, clientId);
        DBObject projection = new BasicDBObject(tokenFieldName, 1);
        DBCursor cursor = null;
        try {
            cursor = getAccessTokenCollection().find(query, projection);
            if (cursor.count() > 0) {
                while (cursor.hasNext()) {
                    OAuth2AccessToken token = mapAccessToken(cursor.next());
                    if (token != null) {
                        accessTokens.add(token);
                    }
                }
            } else {
                LOG.info("Failed to find access token for clientId {}", clientId);
            }
            return accessTokens;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        DBObject query = new BasicDBObject(usernameFieldName, userName);
        DBObject projection = new BasicDBObject(tokenFieldName, 1);
        DBCursor cursor = null;
        try {
            cursor = getAccessTokenCollection().find(query, projection);
            if (cursor.count() > 0) {
                while (cursor.hasNext()) {
                    OAuth2AccessToken token = mapAccessToken(cursor.next());
                    if (token != null) {
                        accessTokens.add(token);
                    }
                }
            } else {
                LOG.info("Failed to find access token for username {}.", userName);
            }
            return accessTokens;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        DBObject query = new BasicDBObject(clientIdFieldName, clientId).append(usernameFieldName, userName);
        DBObject projection = new BasicDBObject(tokenFieldName, 1);
        DBCursor cursor = null;
        try {
            cursor = getAccessTokenCollection().find(query, projection);
            if (cursor.count() > 0) {
                while (cursor.hasNext()) {
                    OAuth2AccessToken token = mapAccessToken(cursor.next());
                    if (token != null) {
                        accessTokens.add(token);
                    }
                }
            } else {
                LOG.info("Failed to find access token for clientId {} and username {}.", clientId, userName);
            }
            return accessTokens;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    protected String extractTokenKey(String value) {
        if (value == null) {
            return null;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
        }

        try {
            byte[] bytes = digest.digest(value.getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, bytes));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
        }
    }

    private final OAuth2AccessToken mapAccessToken(DBObject token) {
        try {
            return deserializeAccessToken((byte[]) token.get(tokenFieldName));
        } catch (IllegalArgumentException e) {
            getAccessTokenCollection().remove(token);
            return null;
        }
    }

    protected byte[] serializeAccessToken(OAuth2AccessToken token) {
        return SerializationUtils.serialize(token);
    }

    protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
        return SerializationUtils.serialize(token);
    }

    protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
        return SerializationUtils.serialize(authentication);
    }

    protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
        return SerializationUtils.deserialize(token);
    }

    protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
        return SerializationUtils.deserialize(token);
    }

    protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
        return SerializationUtils.deserialize(authentication);
    }

    /*
     * Collection and field name customization.
     */

    public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    public void setAccessTokenCollectionName(String accessTokenCollectionName) {
        this.accessTokenCollectionName = accessTokenCollectionName;
    }

    public void setRefreshTokenCollectionName(String refreshTokenCollectionName) {
        this.refreshTokenCollectionName = refreshTokenCollectionName;
    }

    public void setTokenIdFieldName(String tokenIdFieldName) {
        this.tokenIdFieldName = tokenIdFieldName;
    }

    public void setTokenFieldName(String tokenFieldName) {
        this.tokenFieldName = tokenFieldName;
    }

    public void setAuthenticationIdFieldName(String authenticationIdFieldName) {
        this.authenticationIdFieldName = authenticationIdFieldName;
    }

    public void setUsernameFieldName(String usernameFieldName) {
        this.usernameFieldName = usernameFieldName;
    }

    public void setClientIdFieldName(String clientIdFieldName) {
        this.clientIdFieldName = clientIdFieldName;
    }

    public void setAuthenticationFieldName(String authenticationFieldName) {
        this.authenticationFieldName = authenticationFieldName;
    }

    public void setRefreshTokenFieldName(String refreshTokenFieldName) {
        this.refreshTokenFieldName = refreshTokenFieldName;
    }

    public void setWriteConcern(WriteConcern writeConcern) {
        this.writeConcern = writeConcern;
    }
}
