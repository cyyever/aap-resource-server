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

import ai.shao.aap.rs.core.util.ValidationUtils;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for computing SHA-256 hashes of JWT strings, encoded as {@code
 * BASE64URL(SHA-256(ASCII(token_string)))}.
 */
public final class JwtHashUtil {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /**
     * Per-thread SHA-256 digest. {@link MessageDigest} is stateful and not thread-safe, so we cache
     * one instance per thread and call {@link MessageDigest#reset()} between uses. SHA-256 is
     * mandatory in every Java distribution, so the initial {@code getInstance} cannot fail in
     * practice.
     */
    private static final ThreadLocal<MessageDigest> SHA256 =
            ThreadLocal.withInitial(
                    () -> {
                        try {
                            return MessageDigest.getInstance("SHA-256");
                        } catch (NoSuchAlgorithmException e) {
                            throw new AssertionError("SHA-256 must be present in every JRE", e);
                        }
                    });

    /**
     * Computes {@code BASE64URL(SHA-256(UTF-8(jwtString)))}.
     *
     * @throws IllegalArgumentException if the input is null or empty
     */
    public static String computeSha256Hash(String jwtString) {
        if (ValidationUtils.isNullOrEmpty(jwtString)) {
            throw new IllegalArgumentException("JWT string cannot be null or empty");
        }
        MessageDigest digest = SHA256.get();
        digest.reset();
        byte[] hash = digest.digest(jwtString.getBytes(StandardCharsets.UTF_8));
        return URL_ENCODER.encodeToString(hash);
    }

    /**
     * Computes the CT hash (wth).
     *
     * @param ctJwtString the Credential Token (JWT string)
     * @return the base64url-encoded SHA-256 hash of the CT
     * @throws IllegalArgumentException if the CT JWT string is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeWitHash(String ctJwtString) {
        return computeSha256Hash(ctJwtString);
    }

    /**
     * Computes the Access Token hash (ath).
     *
     * @param accessToken the access token
     * @return the base64url-encoded SHA-256 hash of the access token
     * @throws IllegalArgumentException if the access token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeAccessTokenHash(String accessToken) {
        return computeSha256Hash(accessToken);
    }

    // Private constructor to prevent instantiation
    private JwtHashUtil() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
}
