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
package ai.shao.openagentauth.core.server;

import ai.shao.openagentauth.core.model.token.CredentialToken;
import ai.shao.openagentauth.core.model.token.DpopToken;
import ai.shao.openagentauth.core.protocol.ct.CtParser;
import ai.shao.openagentauth.core.protocol.ct.CtValidator;
import ai.shao.openagentauth.core.protocol.dpop.DpopParser;
import ai.shao.openagentauth.core.protocol.dpop.DpopValidator;
import ai.shao.openagentauth.core.server.exception.validation.ServerValidationException;
import ai.shao.openagentauth.core.server.model.request.ResourceRequest;
import ai.shao.openagentauth.core.server.model.validation.ValidationResult;
import ai.shao.openagentauth.core.token.common.TokenValidationResult;
import ai.shao.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Default {@link ResourceServer} implementation. Chains CT then DPoP validation,
 * fail-fast on the first error.
 */
public class DefaultResourceServer implements ResourceServer {

    private static final Logger logger = LoggerFactory.getLogger(DefaultResourceServer.class);

    private static final String CT_NAME = "CT";
    private static final String DPOP_NAME = "DPoP";

    private final CtParser ctParser = new CtParser();
    private final DpopParser dpopParser = new DpopParser();
    private final CtValidator ctValidator;
    private final DpopValidator dpopValidator;

    public DefaultResourceServer(CtValidator ctValidator, DpopValidator dpopValidator) {
        this.ctValidator = ValidationUtils.validateNotNull(ctValidator, "CT validator");
        this.dpopValidator = ValidationUtils.validateNotNull(dpopValidator, "DPoP validator");
    }

    @Override
    public ValidationResult validateRequest(ResourceRequest request) throws ServerValidationException {
        ValidationUtils.validateNotNull(request, "Resource request");

        String ctString = request.getCt();
        String dpopString = request.getDpop();
        if (ValidationUtils.isNullOrEmpty(ctString)) {
            throw new ServerValidationException("CT is required");
        }
        if (ValidationUtils.isNullOrEmpty(dpopString)) {
            throw new ServerValidationException("DPoP is required");
        }

        CredentialToken ct;
        TokenValidationResult<CredentialToken> ctResult;
        try {
            ct = ctParser.parse(SignedJWT.parse(ctString));
            ctResult = ctValidator.validate(ctString);
        } catch (ParseException e) {
            throw new ServerValidationException("Failed to parse CT: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("CT validation failed", e);
            throw new ServerValidationException("CT validation failed: " + e.getMessage(), e);
        }

        if (!ctResult.isValid()) {
            return buildResult(ctResult, null);
        }

        TokenValidationResult<DpopToken> dpopResult;
        try {
            SignedJWT dpopSignedJwt = SignedJWT.parse(dpopString);
            DpopToken dpop = dpopParser.parse(dpopSignedJwt);
            dpopResult = dpopValidator.validate(dpopSignedJwt, dpop, ct);
        } catch (ParseException e) {
            throw new ServerValidationException("Failed to parse DPoP: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("DPoP validation failed", e);
            throw new ServerValidationException("DPoP validation failed: " + e.getMessage(), e);
        }

        return buildResult(ctResult, dpopResult);
    }

    private ValidationResult buildResult(
            TokenValidationResult<CredentialToken> ctResult,
            TokenValidationResult<DpopToken> dpopResult) {
        List<ValidationResult.LayerResult> layerResults = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        layerResults.add(toLayerResult(1, CT_NAME, ctResult.isValid(), ctResult.getErrorMessage()));
        if (!ctResult.isValid() && ctResult.getErrorMessage() != null) {
            errors.add(ctResult.getErrorMessage());
        }

        if (dpopResult != null) {
            layerResults.add(toLayerResult(2, DPOP_NAME, dpopResult.isValid(), dpopResult.getErrorMessage()));
            if (!dpopResult.isValid() && dpopResult.getErrorMessage() != null) {
                errors.add(dpopResult.getErrorMessage());
            }
        }

        boolean valid = ctResult.isValid() && dpopResult != null && dpopResult.isValid();
        return ValidationResult.builder()
                .valid(valid)
                .layerResults(layerResults)
                .errors(errors)
                .build();
    }

    private static ValidationResult.LayerResult toLayerResult(int layer, String name, boolean valid, String message) {
        return ValidationResult.LayerResult.builder()
                .layer(layer)
                .layerName(name)
                .valid(valid)
                .message(valid ? "Validation passed" : message != null ? message : "Validation failed")
                .build();
    }
}
