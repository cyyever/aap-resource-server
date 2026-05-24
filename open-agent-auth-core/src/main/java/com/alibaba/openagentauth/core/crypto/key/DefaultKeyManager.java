/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.core.crypto.key;

import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.resolve.JwksConsumerKeyResolver;
import com.alibaba.openagentauth.core.crypto.key.resolve.KeyResolver;
import com.alibaba.openagentauth.core.crypto.key.resolve.LocalKeyResolver;
import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Default thread-safe {@link KeyManager} backed by a pluggable {@link KeyStore}.
 * All generated keys are Ed25519 ({@code alg=EdDSA}); other algorithms are rejected
 * at the parser level.
 *
 * @see KeyManager
 * @see KeyStore
 * @since 1.0
 */
public class DefaultKeyManager implements KeyManager {

    private static final Logger logger = LoggerFactory.getLogger(DefaultKeyManager.class);

    private final KeyStore keyStore;
    private final List<KeyResolver> keyResolvers;
    private final Map<String, KeyDefinition> keyDefinitions;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public DefaultKeyManager(KeyStore keyStore) {
        this(keyStore, List.of(), Map.of());
    }

    public DefaultKeyManager(KeyStore keyStore, List<KeyResolver> externalResolvers,
                             Map<String, KeyDefinition> keyDefinitions) {
        ValidationUtils.validateNotNull(keyStore, "KeyStore");
        this.keyStore = keyStore;

        List<KeyResolver> allResolvers = new ArrayList<>();
        allResolvers.add(new LocalKeyResolver(this));

        if (externalResolvers != null) {
            allResolvers.addAll(externalResolvers);
        }

        allResolvers.sort(Comparator.comparingInt(KeyResolver::getOrder));
        this.keyResolvers = Collections.unmodifiableList(allResolvers);

        this.keyDefinitions = keyDefinitions != null
                ? Collections.unmodifiableMap(keyDefinitions)
                : Map.of();

        logger.info("DefaultKeyManager initialized with KeyStore: {}, resolvers: {}, keyDefinitions: {}",
                keyStore.getClass().getSimpleName(),
                this.keyResolvers.size(),
                this.keyDefinitions.size());
    }

    @Override
    public void generateKeyPair(String keyId) throws KeyManagementException {

        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }

        lock.writeLock().lock();
        try {
            if (keyStore.exists(keyId)) {
                throw new KeyManagementException("Key with ID '" + keyId + "' already exists");
            }

            OctetKeyPair jwk;
            try {
                jwk = generateEd25519Jwk(keyId);
            } catch (JOSEException e) {
                throw new KeyManagementException("Failed to generate key pair: " + e.getMessage(), e);
            }

            Instant now = Instant.now();
            KeyInfo keyInfo = KeyInfo.builder()
                    .keyId(keyId)
                    .createdAt(now)
                    .activatedAt(now)
                    .active(true)
                    .build();

            keyStore.storeJWK(keyId, jwk, keyInfo);

            logger.info("Generated new Ed25519 key pair: keyId={}", keyId);

        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void rotateKey(String keyId) throws KeyManagementException {

        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }

        lock.writeLock().lock();
        try {
            Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
            if (keyInfoOpt.isEmpty()) {
                throw new KeyManagementException("Key not found for rotation: " + keyId);
            }

            OctetKeyPair newJwk;
            try {
                newJwk = generateEd25519Jwk(keyId);
            } catch (JOSEException e) {
                throw new KeyManagementException("Failed to generate new key pair: " + e.getMessage(), e);
            }

            Instant now = Instant.now();
            KeyInfo newKeyInfo = KeyInfo.builder()
                    .keyId(keyId)
                    .createdAt(now)
                    .activatedAt(now)
                    .active(true)
                    .build();

            keyStore.storeJWK(keyId, newJwk, newKeyInfo);

            logger.info("Rotated key: keyId={}", keyId);

        } finally {
            lock.writeLock().unlock();
        }
    }

    private OctetKeyPair generateEd25519Jwk(String keyId) throws JOSEException {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(keyId).generate();
    }

    @Override
    public List<KeyInfo> getActiveKeys() {
        lock.readLock().lock();
        try {
            List<KeyInfo> activeKeys = new ArrayList<>();
            for (String keyId : keyStore.listKeyIds()) {
                Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
                if (keyInfoOpt.isPresent() && keyInfoOpt.orElseThrow().isActive()) {
                    activeKeys.add(keyInfoOpt.orElseThrow());
                }
            }
            return activeKeys;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public boolean hasKey(String keyId) {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            return false;
        }

        lock.readLock().lock();
        try {
            return keyStore.exists(keyId);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void deleteKey(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }

        lock.writeLock().lock();
        try {
            if (!keyStore.exists(keyId)) {
                throw new KeyManagementException("Key not found for deletion: " + keyId);
            }

            keyStore.delete(keyId);
            logger.info("Deleted key: keyId={}", keyId);

        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public Object getSigningJWK(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }

        lock.readLock().lock();
        try {
            Optional<Object> jwkOpt = keyStore.retrieveJWK(keyId);
            if (jwkOpt.isEmpty()) {
                throw new KeyManagementException("JWK not found: " + keyId);
            }

            Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
            if (keyInfoOpt.isEmpty()) {
                throw new KeyManagementException("Key info not found: " + keyId);
            }

            KeyInfo keyInfo = keyInfoOpt.orElseThrow();
            if (!keyInfo.isActive()) {
                throw new KeyManagementException("Key is not active for signing: " + keyId);
            }

            return jwkOpt.orElseThrow();

        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public Object resolveKey(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }

        KeyDefinition keyDefinition = findKeyDefinitionByKeyId(keyId);

        if (keyDefinition == null || keyResolvers.isEmpty()) {
            logger.debug("No key definition or resolvers for keyId='{}', falling back to local lookup", keyId);
            return getSigningJWK(keyId);
        }

        logger.debug("Resolving key '{}' with definition: {}", keyId, keyDefinition);

        for (KeyResolver resolver : keyResolvers) {
            if (resolver.supports(keyDefinition)) {
                try {
                    JWK resolvedKey = resolver.resolve(keyDefinition);
                    logger.debug("Key '{}' resolved by {}", keyId, resolver.getClass().getSimpleName());
                    return resolvedKey;
                } catch (KeyResolutionException e) {
                    throw new KeyManagementException(
                            "Failed to resolve key '" + keyId + "': " + e.getMessage(), e);
                }
            }
        }

        logger.warn("No KeyResolver supports key definition for keyId='{}', falling back to local lookup", keyId);
        return getSigningJWK(keyId);
    }

    @Override
    public JWK resolveVerificationKey(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }

        Object resolved = resolveKey(keyId);
        if (resolved instanceof JWK jwk) {
            logger.debug("Resolved verification key for keyId='{}': kid={}, kty={}",
                    keyId, jwk.getKeyID(), jwk.getKeyType());
            return jwk;
        }
        throw new KeyManagementException(
                "Resolved key is not a JWK: " + (resolved != null ? resolved.getClass().getName() : "null"));
    }

    private KeyDefinition findKeyDefinitionByKeyId(String keyId) {

        KeyDefinition definition = keyDefinitions.get(keyId);
        if (definition != null) {
            return definition;
        }

        for (KeyDefinition candidate : keyDefinitions.values()) {
            if (keyId.equals(candidate.getKeyId())) {
                return candidate;
            }
        }

        return null;
    }
}
