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
package com.alibaba.openagentauth.core.server.orchestration;

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitParser;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptParser;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.layer.WorkloadIdentityValidator;
import com.alibaba.openagentauth.core.validation.layer.WorkloadProofValidator;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.server.actor.ResourceServer;
import com.alibaba.openagentauth.core.server.exception.validation.ServerValidationException;
import com.alibaba.openagentauth.core.server.model.request.ResourceRequest;
import com.alibaba.openagentauth.core.server.model.validation.ValidationResult;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Default {@link ResourceServer} implementation. Chains WIT then WPT validation,
 * fail-fast on the first error.
 *
 * @see ResourceServer
 * @since 1.0
 */
public class DefaultResourceServer implements ResourceServer {

    private static final Logger logger = LoggerFactory.getLogger(DefaultResourceServer.class);

    private static final String WIT_NAME = "WIT";
    private static final String WPT_NAME = "WPT";

    private final WitParser witParser = new WitParser();
    private final WptParser wptParser = new WptParser();
    private final WorkloadIdentityValidator witValidator;
    private final WorkloadProofValidator wptValidator;

    public DefaultResourceServer(WorkloadIdentityValidator witValidator, WorkloadProofValidator wptValidator) {
        this.witValidator = ValidationUtils.validateNotNull(witValidator, "WIT validator");
        this.wptValidator = ValidationUtils.validateNotNull(wptValidator, "WPT validator");
    }

    @Override
    public ValidationResult validateRequest(ResourceRequest request) throws ServerValidationException {
        ValidationUtils.validateNotNull(request, "Resource request");

        ValidationContext context;
        try {
            context = buildValidationContext(request);
        } catch (ServerValidationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Request validation failed", e);
            throw new ServerValidationException("Request validation failed: " + e.getMessage(), e);
        }

        LayerValidationResult witResult = witValidator.validate(context);
        if (!witResult.isSuccess()) {
            return buildResult(witResult, null);
        }

        LayerValidationResult wptResult = wptValidator.validate(context);
        return buildResult(witResult, wptResult);
    }

    private ValidationContext buildValidationContext(ResourceRequest request) throws ServerValidationException {
        WorkloadIdentityToken wit = parseWit(request.getWit());
        WorkloadProofToken wpt = parseWpt(request.getWpt());

        return ValidationContext.builder()
                .wit(wit)
                .wpt(wpt)
                .httpMethod(request.getHttpMethod())
                .httpUri(request.getHttpUri())
                .httpHeaders(request.getHttpHeaders())
                .httpBody(request.getHttpBody())
                .addAttribute("operationType", request.getOperationType())
                .addAttribute("resourceId", request.getResourceId())
                .addAttribute("context", request.getParameters())
                .build();
    }

    private WorkloadIdentityToken parseWit(String witString) throws ServerValidationException {
        if (ValidationUtils.isNullOrEmpty(witString)) {
            throw new ServerValidationException("WIT is required");
        }
        try {
            return witParser.parse(SignedJWT.parse(witString));
        } catch (ParseException e) {
            throw new ServerValidationException("Failed to parse WIT: " + e.getMessage(), e);
        }
    }

    private WorkloadProofToken parseWpt(String wptString) throws ServerValidationException {
        if (ValidationUtils.isNullOrEmpty(wptString)) {
            throw new ServerValidationException("WPT is required");
        }
        try {
            return wptParser.parse(wptString);
        } catch (Exception e) {
            throw new ServerValidationException("Failed to parse WPT: " + e.getMessage(), e);
        }
    }

    private ValidationResult buildResult(LayerValidationResult witResult, LayerValidationResult wptResult) {
        List<ValidationResult.LayerResult> layerResults = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        layerResults.add(toLayerResult(1, WIT_NAME, witResult));
        if (!witResult.isSuccess()) {
            errors.addAll(witResult.getErrors());
        }

        if (wptResult != null) {
            layerResults.add(toLayerResult(2, WPT_NAME, wptResult));
            if (!wptResult.isSuccess()) {
                errors.addAll(wptResult.getErrors());
            }
        }

        boolean valid = witResult.isSuccess() && wptResult != null && wptResult.isSuccess();
        return ValidationResult.builder()
                .valid(valid)
                .layerResults(layerResults)
                .errors(errors)
                .build();
    }

    private static ValidationResult.LayerResult toLayerResult(int layer, String name, LayerValidationResult r) {
        return ValidationResult.LayerResult.builder()
                .layer(layer)
                .layerName(name)
                .valid(r.isSuccess())
                .message(r.isSuccess() ? "Validation passed" : String.join(", ", r.getErrors()))
                .build();
    }
}
