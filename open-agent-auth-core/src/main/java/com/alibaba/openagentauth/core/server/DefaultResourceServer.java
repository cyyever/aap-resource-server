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
package com.alibaba.openagentauth.core.server;

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitParser;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptParser;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.server.exception.validation.ServerValidationException;
import com.alibaba.openagentauth.core.server.model.request.ResourceRequest;
import com.alibaba.openagentauth.core.server.model.validation.ValidationResult;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Default {@link ResourceServer} implementation. Chains WIT then WPT validation,
 * fail-fast on the first error.
 */
public class DefaultResourceServer implements ResourceServer {

    private static final Logger logger = LoggerFactory.getLogger(DefaultResourceServer.class);

    private static final String WIT_NAME = "WIT";
    private static final String WPT_NAME = "WPT";

    private final WitParser witParser = new WitParser();
    private final WptParser wptParser = new WptParser();
    private final WitValidator witValidator;
    private final WptValidator wptValidator;

    public DefaultResourceServer(WitValidator witValidator, WptValidator wptValidator) {
        this.witValidator = ValidationUtils.validateNotNull(witValidator, "WIT validator");
        this.wptValidator = ValidationUtils.validateNotNull(wptValidator, "WPT validator");
    }

    @Override
    public ValidationResult validateRequest(ResourceRequest request) throws ServerValidationException {
        ValidationUtils.validateNotNull(request, "Resource request");

        String witString = request.getWit();
        String wptString = request.getWpt();
        if (ValidationUtils.isNullOrEmpty(witString)) {
            throw new ServerValidationException("WIT is required");
        }
        if (ValidationUtils.isNullOrEmpty(wptString)) {
            throw new ServerValidationException("WPT is required");
        }

        WorkloadIdentityToken wit;
        TokenValidationResult<WorkloadIdentityToken> witResult;
        try {
            wit = witParser.parse(SignedJWT.parse(witString));
            witResult = witValidator.validate(witString);
        } catch (ParseException e) {
            throw new ServerValidationException("Failed to parse WIT: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("WIT validation failed", e);
            throw new ServerValidationException("WIT validation failed: " + e.getMessage(), e);
        }

        if (!witResult.isValid()) {
            return buildResult(witResult, null);
        }

        TokenValidationResult<WorkloadProofToken> wptResult;
        try {
            SignedJWT wptSignedJwt = SignedJWT.parse(wptString);
            WorkloadProofToken wpt = wptParser.parse(wptSignedJwt);
            wptResult = wptValidator.validate(wptSignedJwt, wpt, wit);
        } catch (ParseException e) {
            throw new ServerValidationException("Failed to parse WPT: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("WPT validation failed", e);
            throw new ServerValidationException("WPT validation failed: " + e.getMessage(), e);
        }

        return buildResult(witResult, wptResult);
    }

    private ValidationResult buildResult(
            TokenValidationResult<WorkloadIdentityToken> witResult,
            TokenValidationResult<WorkloadProofToken> wptResult) {
        List<ValidationResult.LayerResult> layerResults = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        layerResults.add(toLayerResult(1, WIT_NAME, witResult.isValid(), witResult.getErrorMessage()));
        if (!witResult.isValid() && witResult.getErrorMessage() != null) {
            errors.add(witResult.getErrorMessage());
        }

        if (wptResult != null) {
            layerResults.add(toLayerResult(2, WPT_NAME, wptResult.isValid(), wptResult.getErrorMessage()));
            if (!wptResult.isValid() && wptResult.getErrorMessage() != null) {
                errors.add(wptResult.getErrorMessage());
            }
        }

        boolean valid = witResult.isValid() && wptResult != null && wptResult.isValid();
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
