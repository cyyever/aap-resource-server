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
package ai.shao.aap.rs.core.crypto;

import ai.shao.aap.rs.core.model.jwk.Jwk;
import java.util.HashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Converts between RFC 7517 JWK maps and the internal {@link Jwk} record. Only Ed25519 ({@code
 * kty=OKP}, {@code crv=Ed25519}, {@code alg=EdDSA}) is accepted; those parameters are wire-only
 * constants and never stored on the record.
 */
public final class JwkConverter {

    private JwkConverter() {}

    public static Jwk convertMapToJwk(Map<String, Object> jwkMap) {

        String kty = getClaimAsString(jwkMap, "kty");
        if (!"OKP".equals(kty)) {
            throw new IllegalArgumentException("JWK kty must be 'OKP', got: " + kty);
        }
        String crv = getClaimAsString(jwkMap, "crv");
        if (!"Ed25519".equals(crv)) {
            throw new IllegalArgumentException("JWK crv must be 'Ed25519', got: " + crv);
        }
        // alg is optional in RFC 7517; if present, must be EdDSA.
        String alg = getClaimAsString(jwkMap, "alg");
        if (alg != null && !"EdDSA".equals(alg)) {
            throw new IllegalArgumentException("JWK alg must be 'EdDSA', got: " + alg);
        }

        Jwk.Builder builder = Jwk.builder().x(getClaimAsString(jwkMap, "x"));

        String kid = getClaimAsString(jwkMap, "kid");
        if (kid != null) {
            builder.keyId(kid);
        }

        return builder.build();
    }

    public static @Nullable String getClaimAsString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof String s) {
            return s;
        }
        throw new IllegalArgumentException(
                "Invalid claim '%s': expected String, got %s"
                        .formatted(key, value.getClass().getSimpleName()));
    }

    public static Map<String, Object> convertJwkToMap(Jwk jwk) {
        Map<String, Object> jwkMap = new HashMap<>();
        jwkMap.put("kty", "OKP");
        jwkMap.put("crv", "Ed25519");
        jwkMap.put("alg", "EdDSA");
        jwkMap.put("x", jwk.x());
        if (jwk.keyId() != null) {
            jwkMap.put("kid", jwk.keyId());
        }
        return jwkMap;
    }
}
