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
package ai.shao.aap.rs.core.crypto.key;

import ai.shao.aap.rs.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.jwk.JWK;

/**
 * Resolves an Ed25519 verification key by {@code kid}. Implementations are verifier-only —
 * consumers wire their own backend (typically {@link
 * ai.shao.aap.rs.core.crypto.key.resolve.JwksConsumerKeyResolver} for a remote JWKS
 * endpoint, but file-backed or KMS-backed adapters are equally valid). Implementations must be
 * thread-safe.
 */
public interface KeyManager {

    JWK resolveVerificationKey(String keyId) throws KeyResolutionException;
}
