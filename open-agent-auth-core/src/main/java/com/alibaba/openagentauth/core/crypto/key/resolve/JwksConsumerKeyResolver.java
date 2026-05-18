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
package com.alibaba.openagentauth.core.crypto.key.resolve;

import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link KeyResolver} that loads keys from remote JWKS endpoints, with per-consumer
 * caching, TTL-based expiry, and a key-not-found refetch throttle to absorb upstream
 * key rotation without thundering-herd refetches.
 *
 * @see KeyResolver
 * @since 1.0
 */
public class JwksConsumerKeyResolver implements KeyResolver {

    private static final Logger logger = LoggerFactory.getLogger(JwksConsumerKeyResolver.class);

    /** Default time-to-live for a cached JWK set before forcing a refetch. */
    public static final Duration DEFAULT_JWKS_TTL = Duration.ofMinutes(10);

    /** Default minimum interval between key-not-found refetches per consumer. */
    public static final Duration DEFAULT_NOT_FOUND_RETRY_THROTTLE = Duration.ofSeconds(30);

    private final Map<String, String> consumerEndpoints;
    private final Duration jwksTtl;
    private final Duration notFoundRetryThrottle;

    /** Cached JWK sets keyed by consumer name, each tagged with its expiry. */
    private final ConcurrentHashMap<String, CachedJwks> jwkSetCache = new ConcurrentHashMap<>();

    /**
     * Last time a key-not-found refetch was attempted per consumer. Used to throttle
     * back-to-back refetches when an attacker (or a misconfigured client) keeps asking
     * for an unknown {@code kid}.
     */
    private final ConcurrentHashMap<String, Instant> lastNotFoundFetch = new ConcurrentHashMap<>();

    public JwksConsumerKeyResolver(Map<String, String> consumerEndpoints) {
        this(consumerEndpoints, DEFAULT_JWKS_TTL, DEFAULT_NOT_FOUND_RETRY_THROTTLE);
    }

    public JwksConsumerKeyResolver(Map<String, String> consumerEndpoints,
                                   Duration jwksTtl,
                                   Duration notFoundRetryThrottle) {
        if (consumerEndpoints == null) {
            throw new IllegalArgumentException("Consumer endpoints map cannot be null");
        }
        this.consumerEndpoints = consumerEndpoints;
        this.jwksTtl = jwksTtl;
        this.notFoundRetryThrottle = notFoundRetryThrottle;
        logger.info("JwksConsumerKeyResolver initialized: {} consumer(s) {}, ttl={}, notFoundThrottle={}",
                consumerEndpoints.size(), consumerEndpoints.keySet(), jwksTtl, notFoundRetryThrottle);
    }

    @Override
    public boolean supports(KeyDefinition keyDefinition) {
        if (keyDefinition == null || !keyDefinition.isRemoteKey()) {
            return false;
        }
        return consumerEndpoints.containsKey(keyDefinition.getJwksConsumer());
    }

    @Override
    public JWK resolve(KeyDefinition keyDefinition) throws KeyResolutionException {
        String consumerName = keyDefinition.getJwksConsumer();
        String keyId = keyDefinition.getKeyId();

        String jwksEndpoint = consumerEndpoints.get(consumerName);
        if (jwksEndpoint == null || jwksEndpoint.isBlank()) {
            throw new KeyResolutionException(
                    "No JWKS endpoint configured for consumer '" + consumerName + "'");
        }

        try {
            JWKSet jwkSet = getOrFetch(consumerName, jwksEndpoint);
            JWK resolvedKey = jwkSet.getKeyByKeyId(keyId);

            if (resolvedKey == null && canRefetchAfterNotFound(consumerName)) {
                logger.info("Key '{}' not found in cached JWKS for consumer '{}', forcing refresh",
                        keyId, consumerName);
                lastNotFoundFetch.put(consumerName, Instant.now());
                jwkSetCache.remove(consumerName);
                jwkSet = getOrFetch(consumerName, jwksEndpoint);
                resolvedKey = jwkSet.getKeyByKeyId(keyId);
            }

            if (resolvedKey == null) {
                throw new KeyResolutionException(
                        "Key '" + keyId + "' not found in JWKS from consumer '" +
                                consumerName + "' at " + jwksEndpoint);
            }

            logger.debug("Resolved remote key: keyId={}, consumer={}, keyType={}",
                    keyId, consumerName, resolvedKey.getKeyType());
            return resolvedKey;
        } catch (KeyResolutionException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyResolutionException(
                    "Failed to resolve key '" + keyId + "' from consumer '" +
                            consumerName + "': " + e.getMessage(), e);
        }
    }

    private JWKSet getOrFetch(String consumerName, String jwksEndpoint) {
        Instant now = Instant.now();
        CachedJwks cached = jwkSetCache.get(consumerName);
        if (cached != null && now.isBefore(cached.expiresAt)) {
            return cached.set;
        }
        // computeIfAbsent locks per-key, collapsing concurrent fetches to one
        return jwkSetCache.compute(consumerName, (name, existing) -> {
            if (existing != null && Instant.now().isBefore(existing.expiresAt)) {
                return existing;
            }
            logger.info("Fetching JWKS from consumer '{}': {}", name, jwksEndpoint);
            try {
                JWKSet set = JWKSet.load(new URL(jwksEndpoint));
                return new CachedJwks(set, Instant.now().plus(jwksTtl));
            } catch (Exception e) {
                throw new RuntimeException(
                        "Failed to fetch JWKS from '" + name + "' at " + jwksEndpoint, e);
            }
        }).set;
    }

    private boolean canRefetchAfterNotFound(String consumerName) {
        Instant last = lastNotFoundFetch.get(consumerName);
        return last == null || Duration.between(last, Instant.now()).compareTo(notFoundRetryThrottle) >= 0;
    }

    @Override
    public int getOrder() {
        return 10;
    }

    /** Drops every cached JWK set, forcing fresh fetches on next resolve. */
    public void clearCache() {
        jwkSetCache.clear();
        lastNotFoundFetch.clear();
        logger.info("Cleared all JWKS consumer caches");
    }

    /** Drops a specific consumer's cached JWK set. */
    public void clearCache(String consumerName) {
        jwkSetCache.remove(consumerName);
        lastNotFoundFetch.remove(consumerName);
        logger.info("Cleared JWKS cache for consumer: {}", consumerName);
    }

    public String getConsumerEndpoint(String consumerName) {
        return consumerEndpoints.get(consumerName);
    }

    private record CachedJwks(JWKSet set, Instant expiresAt) {}
}
