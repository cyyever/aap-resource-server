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
package ai.shao.aap.rs.core.crypto.verify;

import ai.shao.aap.rs.core.crypto.key.KeyManager;
import ai.shao.aap.rs.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves a verification key from {@link KeyManager} and verifies a JWT signature. Only Ed25519
 * ({@code alg=EdDSA}) is supported.
 */
public final class SignatureVerificationUtils {

    private static final Logger logger = LoggerFactory.getLogger(SignatureVerificationUtils.class);

    private SignatureVerificationUtils() {}

    public static boolean verifySignature(
            SignedJWT signedJwt, KeyManager keyManager, String verificationKeyId) {

        JWSAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();
        String headerKeyId = signedJwt.getHeader().getKeyID();
        logger.debug(
                "Verifying signature - header kid: {}, algorithm: {}, verificationKeyId: {}",
                headerKeyId,
                algorithm,
                verificationKeyId);

        if (!JWSAlgorithm.EdDSA.equals(algorithm)) {
            logger.warn("Unsupported algorithm: {} (only EdDSA is allowed)", algorithm);
            return false;
        }

        try {
            JWK verificationKey = keyManager.resolveVerificationKey(verificationKeyId);
            JWSVerifier verifier = createVerifier(verificationKey);
            boolean isValid = signedJwt.verify(verifier);

            if (!isValid) {
                logger.warn(
                        "Signature verification failed - header kid: {}, verificationKeyId: {}",
                        headerKeyId,
                        verificationKeyId);
            }
            return isValid;
        } catch (KeyResolutionException e) {
            logger.error(
                    "Failed to resolve verification key for keyId '{}': {}",
                    verificationKeyId,
                    e.getMessage());
            return false;
        } catch (JOSEException e) {
            logger.error("Error during signature verification: {}", e.getMessage());
            return false;
        }
    }

    public static JWSVerifier createVerifier(JWK jwk) throws JOSEException {
        if (jwk instanceof OctetKeyPair okp) {
            return new Ed25519Verifier(okp.toPublicJWK());
        }
        throw new IllegalArgumentException("Unsupported JWK type: " + jwk.getKeyType());
    }
}
