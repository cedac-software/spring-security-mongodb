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
package com.cedac.security.oauth2.provider.client;

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
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;

/**
 * MongoOperations implementation of {@link ClientDetailsService} and {@link ClientRegistrationService}.
 *
 * @author mauro.franceschini@cedac.com
 * @since 1.0.0
 */
public class MongoClientDetailsService implements ClientDetailsService, ClientRegistrationService, InitializingBean {
    private static final Marker CLIENT = MarkerFactory.getDetachedMarker("client-details");
    private static final Logger LOG = LoggerFactory.getLogger(MongoClientDetailsService.class);

    private static final WriteConcern DEFAULT_WRITE_CONCERN = WriteConcern.NORMAL;

    private static final String DEFAULT_CLIENT_DETAILS_COLLECTION_NAME = "client_details";

    private static final String DEFAULT_CLIENT_ID_FIELD_NAME = "clientId";
    private static final String DEFAULT_RESOURCE_IDS_FIELD_NAME = "resourceIds";
    private static final String DEFAULT_CLIENT_SECRET_FIELD_NAME = "clientSecret";
    private static final String DEFAULT_SCOPE_FIELD_NAME = "scope";
    private static final String DEFAULT_AUTHORIZED_GRANT_TYPES_FIELD_NAME = "authorizedGrantTypes";
    private static final String DEFAULT_REGISTERED_REDIRECT_URIS_FIELD_NAME = "registeredRedirectUris";
    private static final String DEFAULT_AUTHORITIES_FIELD_NAME = "authorities";
    private static final String DEFAULT_ACCESS_TOKEN_VALIDITY_FIELD_NAME = "accessTokenValidity";
    private static final String DEFAULT_REFRESH_TOKEN_VALIDITY_FIELD_NAME = "refreshTokenValidity";
    private static final String DEFAULT_ADDITIONAL_INFORMATION_FIELD_NAME = "additionalInformation";
    private static final String DEFAULT_AUTO_APPROVE_FIELD_NAME = "autoapprove";

    private final DB db;

    private String clientDetailsCollectionName = DEFAULT_CLIENT_DETAILS_COLLECTION_NAME;

    private String clientIdFieldName = DEFAULT_CLIENT_ID_FIELD_NAME;
    private String resourceIdsFieldName = DEFAULT_RESOURCE_IDS_FIELD_NAME;
    private String clientSecretFieldName = DEFAULT_CLIENT_SECRET_FIELD_NAME;
    private String scopeFieldName = DEFAULT_SCOPE_FIELD_NAME;
    private String authorizedGrantTypesFieldName = DEFAULT_AUTHORIZED_GRANT_TYPES_FIELD_NAME;
    private String registeredRedirectUrisFieldName = DEFAULT_REGISTERED_REDIRECT_URIS_FIELD_NAME;
    private String authoritiesFieldName = DEFAULT_AUTHORITIES_FIELD_NAME;
    private String accessTokenValidityFieldName = DEFAULT_ACCESS_TOKEN_VALIDITY_FIELD_NAME;
    private String refreshTokenValidityFieldName = DEFAULT_REFRESH_TOKEN_VALIDITY_FIELD_NAME;
    private String additionalInformationFieldName = DEFAULT_ADDITIONAL_INFORMATION_FIELD_NAME;
    private String autoApproveFieldName = DEFAULT_AUTO_APPROVE_FIELD_NAME;

    private WriteConcern writeConcern = DEFAULT_WRITE_CONCERN;

    private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();

    public MongoClientDetailsService(Mongo mongo, String databaseName) {
        this(mongo.getDB(databaseName));
    }

    public MongoClientDetailsService(DB db) {
        Assert.notNull(db, "DB is required");
        this.db = db;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (!this.db.collectionExists(clientDetailsCollectionName)) {
            LOG.trace(CLIENT, "Creating {} collection", clientDetailsCollectionName);

            DBCollection collection = this.db.createCollection(clientDetailsCollectionName, new BasicDBObject());
            collection.createIndex(new BasicDBObject(clientIdFieldName, 1),
                    new BasicDBObject("name", clientDetailsCollectionName + "_" + clientIdFieldName + "_ix")
                            .append("unique", 1));

            LOG.debug(CLIENT, "Collection {} successfully created and indexed", clientDetailsCollectionName);
        }
    }

    private final DBCollection getClientDetailsCollection() {
        return db.getCollection(clientDetailsCollectionName);
    }

    public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {
        DBObject query = new BasicDBObject(clientIdFieldName, clientId);
        DBObject entry = getClientDetailsCollection().findOne(query);
        if (entry == null) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }
        return toClientDetails(entry);
    }

    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        DBObject query = new BasicDBObject(clientIdFieldName, clientDetails.getClientId());
        if (getClientDetailsCollection().count(query) == 0) {
            DBObject entry = toDBObject(clientDetails);
            getClientDetailsCollection().insert(entry, writeConcern);
        } else {
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId());
        }
    }

    public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        DBObject query = new BasicDBObject(clientIdFieldName, clientDetails.getClientId());
        DBObject entry = getClientDetailsCollection().findOne(query);
        if (entry != null) {
            updateDBObject(entry, clientDetails);
            getClientDetailsCollection().save(entry, writeConcern);
        } else {
            throw new NoSuchClientException("No client found with id = " + clientDetails.getClientId());
        }
    }

    public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        DBObject query = new BasicDBObject(clientIdFieldName, clientId);
        DBObject entry = getClientDetailsCollection().findOne(query);
        if (entry != null) {
            entry.put(clientSecretFieldName, passwordEncoder.encode(secret));
            getClientDetailsCollection().save(entry, writeConcern);
        } else {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
    }

    public void removeClientDetails(String clientId) throws NoSuchClientException {
        DBObject query = new BasicDBObject(clientIdFieldName, clientId);
        WriteResult result = getClientDetailsCollection().remove(query, writeConcern);
        if (result.getN() != 1) {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
    }

    public List<ClientDetails> listClientDetails() {
        DBCursor cursor = null;
        try {
            cursor = getClientDetailsCollection().find();
            List<ClientDetails> clientDetails = new ArrayList<ClientDetails>();
            while (cursor.hasNext()) {
                clientDetails.add(toClientDetails(cursor.next()));
            }
            return clientDetails;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private ClientDetails toClientDetails(DBObject dbo) {
        final String clientId = (String) dbo.get(clientIdFieldName);
        final String resourceIds = collectionToCommaDelimitedString((Collection) dbo.get(resourceIdsFieldName));
        final String scopes = collectionToCommaDelimitedString((Collection) dbo.get(scopeFieldName));
        final String grantTypes = collectionToCommaDelimitedString((Collection) dbo.get(authorizedGrantTypesFieldName));
        final String authorities = collectionToCommaDelimitedString((Collection) dbo.get(authoritiesFieldName));
        final String redirectUris = collectionToCommaDelimitedString(
                (Collection) dbo.get(registeredRedirectUrisFieldName));
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities,
                redirectUris);
        clientDetails.setClientSecret((String) dbo.get(clientSecretFieldName));
        clientDetails.setAccessTokenValiditySeconds((Integer) dbo.get(accessTokenValidityFieldName));
        clientDetails.setRefreshTokenValiditySeconds((Integer) dbo.get(refreshTokenValidityFieldName));
        Object autoApprove = dbo.get(autoApproveFieldName);
        if (autoApprove != null) {
            if (autoApprove instanceof String) {
                clientDetails.setAutoApproveScopes(Collections.singleton((String) autoApprove));
            } else {
                clientDetails.setAutoApproveScopes((Collection<String>) dbo.get(autoApproveFieldName));
            }
        }
        DBObject additionalInfo = (DBObject) dbo.get(additionalInformationFieldName);
        if (additionalInfo != null) {
            for (String key : additionalInfo.keySet()) {
                clientDetails.addAdditionalInformation(key, additionalInfo.get(key));
            }
        }
        return clientDetails;
    }

    private DBObject toDBObject(ClientDetails clientDetails) {
        BasicDBObject dbo = new BasicDBObject(clientIdFieldName, clientDetails.getClientId());
        if (clientDetails.isSecretRequired()) {
            dbo.put(clientSecretFieldName, passwordEncoder.encode(clientDetails.getClientSecret()));
        }
        updateDBObject(dbo, clientDetails);
        return dbo;
    }

    private void updateDBObject(DBObject dbo, ClientDetails clientDetails) {
        dbo.put(resourceIdsFieldName, clientDetails.getResourceIds());
        dbo.put(scopeFieldName, clientDetails.getScope());
        dbo.put(authorizedGrantTypesFieldName, clientDetails.getAuthorizedGrantTypes());
        dbo.put(registeredRedirectUrisFieldName, clientDetails.getRegisteredRedirectUri());
        dbo.put(authoritiesFieldName, AuthorityUtils.authorityListToSet(clientDetails.getAuthorities()));
        dbo.put(accessTokenValidityFieldName, clientDetails.getAccessTokenValiditySeconds());
        dbo.put(refreshTokenValidityFieldName, clientDetails.getRefreshTokenValiditySeconds());
        dbo.put(additionalInformationFieldName, clientDetails.getAdditionalInformation());
        Set<String> autoApprove = new HashSet<String>();
        for (String scope : clientDetails.getScope()) {
            if (clientDetails.isAutoApprove(scope)) {
                autoApprove.add(scope);
            }
        }
        dbo.put(autoApproveFieldName, autoApprove.size() == 1 ? autoApprove.iterator().next() : autoApprove);
    }

    /*
     * Configuration properties.
     */

    public void setClientDetailsCollectionName(String clientDetailsCollectionName) {
        this.clientDetailsCollectionName = clientDetailsCollectionName;
    }

    public void setClientIdFieldName(String clientIdFieldName) {
        this.clientIdFieldName = clientIdFieldName;
    }

    public void setResourceIdsFieldName(String resourceIdsFieldName) {
        this.resourceIdsFieldName = resourceIdsFieldName;
    }

    public void setClientSecretFieldName(String clientSecretFieldName) {
        this.clientSecretFieldName = clientSecretFieldName;
    }

    public void setScopeFieldName(String scopeFieldName) {
        this.scopeFieldName = scopeFieldName;
    }

    public void setAuthorizedGrantTypesFieldName(String authorizedGrantTypesFieldName) {
        this.authorizedGrantTypesFieldName = authorizedGrantTypesFieldName;
    }

    public void setRegisteredRedirectUrisFieldName(String registeredRedirectUrisFieldName) {
        this.registeredRedirectUrisFieldName = registeredRedirectUrisFieldName;
    }

    public void setAuthoritiesFieldName(String authoritiesFieldName) {
        this.authoritiesFieldName = authoritiesFieldName;
    }

    public void setAccessTokenValidityFieldName(String accessTokenValidityFieldName) {
        this.accessTokenValidityFieldName = accessTokenValidityFieldName;
    }

    public void setRefreshTokenValidityFieldName(String refreshTokenValidityFieldName) {
        this.refreshTokenValidityFieldName = refreshTokenValidityFieldName;
    }

    public void setAdditionalInformationFieldName(String additionalInformationFieldName) {
        this.additionalInformationFieldName = additionalInformationFieldName;
    }

    public void setAutoApproveFieldName(String autoApproveFieldName) {
        this.autoApproveFieldName = autoApproveFieldName;
    }

    public void setWriteConcern(WriteConcern writeConcern) {
        this.writeConcern = writeConcern;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
}
