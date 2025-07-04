/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.webhook_signature_validator.configuration;

//import io.gravitee.plugin.annotation.ConfigurationEvaluator;
import io.gravitee.policy.api.PolicyConfiguration;
import lombok.Getter;
import lombok.Setter;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
@Getter
@Setter
public class WebhookSignatureValidatorPolicyConfiguration implements PolicyConfiguration {

    private String sourceSignatureHeader;

    private SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();

    private String algorithm;

    private String secret;
}
