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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ai.shao.aap.rs.core.crypto.key.KeyManager;
import ai.shao.aap.rs.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SignatureVerificationUtils}.
 *
 * @since 1.0
 */
@DisplayName("SignatureVerificationUtils Tests")
class SignatureVerificationUtilsTest {

    private static final String VERIFICATION_KEY_ID = "test-key";

    private OctetKeyPair edKey;

    @BeforeEach
    void setUp() throws JOSEException {
        edKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("ed-key").generate();
    }

    @Nested
    @DisplayName("verifySignature Tests")
    class VerifySignatureTests {

        @Test
        @DisplayName("Should verify valid Ed25519 signature")
        void shouldVerifyValidEd25519Signature() throws Exception {
            SignedJWT signedJwt = createSignedJwt(new Ed25519Signer(edKey), edKey.getKeyID());

            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString())).thenReturn(edKey.toPublicJWK());

            boolean result =
                    SignatureVerificationUtils.verifySignature(
                            signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false for invalid signature")
        void shouldReturnFalseForInvalidSignature() throws Exception {
            SignedJWT signedJwt = createSignedJwt(new Ed25519Signer(edKey), edKey.getKeyID());

            OctetKeyPair differentKey =
                    new OctetKeyPairGenerator(Curve.Ed25519).keyID("different-key").generate();
            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString()))
                    .thenReturn(differentKey.toPublicJWK());

            boolean result =
                    SignatureVerificationUtils.verifySignature(
                            signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when KeyManager throws exception")
        void shouldReturnFalseWhenKeyManagerThrowsException() throws Exception {
            SignedJWT signedJwt = createSignedJwt(new Ed25519Signer(edKey), edKey.getKeyID());

            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString()))
                    .thenThrow(new KeyResolutionException("Key not found"));

            boolean result =
                    SignatureVerificationUtils.verifySignature(
                            signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject non-EdDSA algorithm")
        void shouldRejectNonEdDsaAlgorithm() throws Exception {
            // Build a JWT carrying alg=RS256 and let SignatureVerificationUtils short-circuit.
            String header =
                    com.nimbusds.jose.util.Base64URL.encode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}")
                            .toString();
            String payload =
                    com.nimbusds.jose.util.Base64URL.encode("{\"sub\":\"test\"}").toString();
            String fakeJwt = header + "." + payload + ".AAAA";
            SignedJWT parsed = SignedJWT.parse(fakeJwt);

            KeyManager keyManager = mock(KeyManager.class);

            boolean result =
                    SignatureVerificationUtils.verifySignature(
                            parsed, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("createVerifier Tests")
    class CreateVerifierTests {

        @Test
        @DisplayName("Should create Ed25519 verifier from OctetKeyPair")
        void shouldCreateEd25519Verifier() throws JOSEException {
            JWSVerifier verifier = SignatureVerificationUtils.createVerifier(edKey.toPublicJWK());

            assertThat(verifier).isNotNull();
            assertThat(verifier.supportedJWSAlgorithms()).contains(JWSAlgorithm.EdDSA);
        }

        @Test
        @DisplayName("Should throw exception for unsupported key type")
        void shouldThrowExceptionForUnsupportedKeyType() throws JOSEException {
            OctetSequenceKey octKey =
                    new OctetSequenceKeyGenerator(256).keyID("oct-key").generate();

            assertThatThrownBy(() -> SignatureVerificationUtils.createVerifier(octKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Unsupported JWK type");
        }
    }

    private SignedJWT createSignedJwt(com.nimbusds.jose.JWSSigner signer, String keyId)
            throws JOSEException {
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .issuer("https://example.com")
                        .subject("test-subject")
                        .expirationTime(
                                Date.from(
                                        Instant.ofEpochMilli(
                                                System.currentTimeMillis() + 3600_000)))
                        .build();

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(keyId).build(), claimsSet);
        signedJwt.sign(signer);
        return signedJwt;
    }
}
