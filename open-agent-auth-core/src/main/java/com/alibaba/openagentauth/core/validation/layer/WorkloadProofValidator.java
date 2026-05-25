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
package com.alibaba.openagentauth.core.validation.layer;

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validator for Workload Proof Token (WPT) verification.
 * Delegates to {@link WptValidator} for signature, expiration, claims, and wth checks.
 */
public class WorkloadProofValidator implements LayerValidator {

    private static final Logger logger = LoggerFactory.getLogger(WorkloadProofValidator.class);

    private final WptValidator wptValidator;

    public WorkloadProofValidator(WptValidator wptValidator) {
        ValidationUtils.validateNotNull(wptValidator, "WptValidator");
        this.wptValidator = wptValidator;
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 2: Workload Proof validation");

        if (context.getWpt() == null) {
            logger.error("WPT is missing from validation context");
            return LayerValidationResult.failure(
                "WPT is required but not present in the validation context"
            );
        }

        if (context.getWit() == null) {
            logger.error("WIT is missing from validation context, required for WPT verification");
            return LayerValidationResult.failure(
                "WIT is required for WPT verification but not present in the validation context"
            );
        }

        WorkloadProofToken wpt = context.getWpt();
        WorkloadIdentityToken wit = context.getWit();

        try {
            var result = wptValidator.validate(context.getWptSignedJwt(), wpt, wit);

            if (!result.isValid()) {
                logger.error("Layer 2: Workload Proof validation failed: {}", result.getErrorMessage());
                return LayerValidationResult.failure(
                    result.getErrorMessage(),
                    "Layer 2 WPT Validation"
                );
            }

            logger.debug("Layer 2: Workload Proof validation passed successfully");
            return LayerValidationResult.success("Layer 2: WPT validation completed successfully");

        } catch (Exception e) {
            logger.error("Error validating WPT", e);
            return LayerValidationResult.failure(
                "WPT validation failed: " + e.getMessage(),
                "Layer 2 WPT Validation"
            );
        }
    }

    @Override
    public String getName() {
        return "Layer 2: Workload Proof Validator";
    }

    @Override
    public double getOrder() {
        return 2.0;
    }
}
