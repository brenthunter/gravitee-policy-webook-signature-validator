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
package io.gravitee.policy.webook_signature_validator;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.webook_signature_validator.configuration.SchemeTypeConfiguration;
import io.gravitee.policy.webook_signature_validator.configuration.WebhookSignatureValidatorPolicyConfiguration;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class WebhookSignatureValidatorPolicy {

    private static final String WEBHOOK_SIGNATURE_INVALID_SIGNATURE = "WEBHOOK_SIGNATURE_INVALID_SIGNATURE";
    private static final String WEBHOOK_SIGNATURE_NOT_FOUND = "WEBHOOK_SIGNATURE_NOT_FOUND";
    private static final String WEBHOOK_SIGNATURE_NOT_BASE64 = "WEBHOOK_SIGNATURE_NOT_BASE64";
    private static final String WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID = "WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID";

    static final String WEBHOOK_HEADER_SIGNATURE = "X-Shopify-Webhook-HMAC";

    /**
     * Policy configuration
     */
    private final WebhookSignatureValidatorPolicyConfiguration configuration;

    public WebhookSignatureValidatorPolicy(final WebhookSignatureValidatorPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequestContent
    public ReadWriteStream<Buffer> onRequestContent(Request request, Response response, ExecutionContext context, PolicyChain chain) {
        // Extract the signature according to the scheme
        log.info("DEBUG: Starting WebhookSignatureValidatorPolicy...");

        String secret2 = context.getTemplateEngine().getValue(configuration.getSecret(), String.class);
        String algorithm = configuration.getAlgorithm();

        return new BufferedReadWriteStream() {
            Buffer buffer = Buffer.buffer();

            @Override
            public SimpleReadWriteStream<Buffer> write(Buffer content) {
                buffer.appendBuffer(content);
                return this;
            }

            @Override
            public void end() {
                String sourceSigHeader = null;
                List<String> addedHeaders = null;

                try {
                    sourceSigHeader = context.getTemplateEngine().getValue(configuration.getSourceSignatureHeader(), String.class);
                    log.info("DEBUG: Supplied HMAC Signature: {}", sourceSigHeader); // "He+KRJq..."
                    if (sourceSigHeader == "" || sourceSigHeader.isBlank() || sourceSigHeader == null) {
                        chain.failWith(PolicyResult.failure(WEBHOOK_SIGNATURE_NOT_FOUND, 401, "Webhook Signature Not Found"));
                        return;
                    }
                } catch (Exception e) {
                    chain.failWith(PolicyResult.failure(WEBHOOK_SIGNATURE_NOT_FOUND, 401, "Webhook Signature Not Found"));
                    return;
                }

                log.info("DEBUG: Signature validation requires additional headers?: {}", configuration.getSchemeType().isEnabled()); // true|false
                if (configuration.getSchemeType().isEnabled()) {
                    addedHeaders = new ArrayList<>(configuration.getSchemeType().getHeaders());

                    if (addedHeaders.size() > 0) {
                        int i = 0;
                        while (i < addedHeaders.size()) {
                            log.debug("DEBUG: Header '{}' = '{}'", addedHeaders.get(i), request.headers().get(addedHeaders.get(i)));
                            if (request.headers().get(addedHeaders.get(i)) == null) {
                                chain.failWith(
                                    PolicyResult.failure(
                                        WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID,
                                        401,
                                        "A required webhook header value is invalid or missing"
                                    )
                                );
                                return;
                            }
                            i++;
                        }
                    } else {
                        chain.failWith(
                            PolicyResult.failure(
                                WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID,
                                401,
                                "Webhook additional headers not valid or not found"
                            )
                        );
                        return;
                    }
                }

                log.info("DEBUG: Secret: {}", secret2); // "mySecret"
                log.info("DEBUG: Algorithm: {}", algorithm); // "Hmac512"
                log.info("DEBUG: Request Body: {}", buffer.toString());

                log.info("DEBUG: -> Configuration retrieval completed.");

                // Get request payload
                String data = buffer.toString();

                // Prepare data (add additional headers to payload if needed)
                if (configuration.getSchemeType().isEnabled()) {
                    int i = 0;
                    String tmpData = "";
                    while (i < addedHeaders.size()) {
                        log.info("DEBUG: Adding '{}' to data...", request.headers().get(addedHeaders.get(i)));
                        tmpData += request.headers().get(addedHeaders.get(i));
                        i++;
                    }
                    data = tmpData + data;
                }
                log.info("DEBUG: (final) data (for signature creation) '{}'", data);

                // Generate and Validate HMAC Signature...
                if (!validateHmacSignature(data, sourceSigHeader, secret2, algorithm)) {
                    log.error("DEBUG_FINAL: Signature is NOT valid!");
                    chain.failWith(PolicyResult.failure(WEBHOOK_SIGNATURE_INVALID_SIGNATURE, 401, "Invalid Webhook Signature"));
                    return;
                }
                log.info("DEBUG_FINAL: Signature is valid.");
                chain.doNext(request, response);
            }
        };
    }

    // Method to generate HMAC signature
    private String generateHmacSignature(String data, String secretKey, String algorithm) {
        try {
            // Create a SecretKeySpec from the key
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), algorithm);

            // Initialize the Mac instance with the specified algorithm
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);

            // Generate the HMAC hash of the data
            byte[] hmacHash = mac.doFinal(data.getBytes("UTF-8"));

            log.info("DEBUG: Generated HMAC signature: {}", Base64.getEncoder().encodeToString(hmacHash));

            // Return the Base64 encoded HMAC signature
            return Base64.getEncoder().encodeToString(hmacHash);
        } catch (Exception ex) {
            log.error("DEBUG: Exception - Error generating HMAC signature!");
            log.error(ex.getMessage());
            //request.metrics().setMessage(ex.getMessage());
            return null;
        }
    }

    // Method to validate the HMAC signature
    private boolean validateHmacSignature(String data, String providedSignature, String secretKey, String algorithm) {
        log.info("DEBUG: Validating HMAC signature...");
        // Generate the HMAC signature based on the data and the secret key
        String generatedSignature = generateHmacSignature(data, secretKey, algorithm);

        // Compare the generated signature with the provided signature (ignoring case)
        return generatedSignature.equals(providedSignature);
    }
}
