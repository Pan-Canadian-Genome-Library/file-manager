package bio.overture.song.server.config;

import static java.lang.Boolean.TRUE;

import bio.overture.song.core.retry.DefaultRetryListener;
import bio.overture.song.core.retry.RetryPolicies;
import bio.overture.song.server.security.authz.AuthZRestClient;
import bio.overture.song.server.service.StorageService;
import bio.overture.song.server.service.ValidationService;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.listener.RetryListenerSupport;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/** */
@Slf4j
@Configuration
@Profile("pcglauthz")
public class StorageClientAuthZConfig {

  @Autowired private ValidationService validationService;

  @Autowired private AuthZRestClient authZRestClient;
  @Autowired private PCGLAuthZConfig pcglAuthZConfig;

  @Value("${score.url}")
  private String storageUrl;

  /**
   * This custom RetryListener is added to the StorageClientAuthZConfig retryTemplate. It listens
   * for any failures that are caused by an Unauthorized error from the rest template, when those
   * occur we can clear the stored service token so that the retry attempt will be forced to fetch a
   * fresh token.
   */
  public class ResetUnauthorizedTokenRetryListener extends RetryListenerSupport {

    @Override
    public <T, E extends Throwable> void onError(
        RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
      log.info("RetryTemplate onError");
      if (throwable instanceof HttpClientErrorException) {
        HttpClientErrorException clientError = (HttpClientErrorException) throwable;

        if (clientError.getStatusCode() == HttpStatus.UNAUTHORIZED) {
          // Service Token failed verification by File-Transfer (Storage Service)
          // Clear the token so a new one will be fetched to build the retry request
          authZRestClient.clearServiceVerificationToken();
        } else {
          // Other ClientErrorExceptions indicate our request is malformed and should not
          // be retried
          context.setExhaustedOnly();
        }
      }
    }
  }

  @Bean
  public StorageService storageService() {
    return StorageService.builder()
        .restTemplate(serviceTokenInjectedRestTemplate())
        .retryTemplate(unauthorizedServiceTokenRetryTemplate())
        .storageUrl(storageUrl)
        .validationService(validationService)
        .build();
  }

  private RetryTemplate unauthorizedServiceTokenRetryTemplate() {
    final int maxRetries = 2;

    val retryTemplate = new RetryTemplate();

    // Retry all the default retryable exceptions, plus also
    // HttpClientErrorExceptions which include
    // UNAUTHORIZED
    Map<Class<? extends Throwable>, Boolean> retryableExceptions =
        ImmutableMap.<Class<? extends Throwable>, Boolean>builder()
            .putAll(RetryPolicies.getRetryableExceptions())
            .put(HttpClientErrorException.class, TRUE)
            .build();
    retryTemplate.setRetryPolicy(new SimpleRetryPolicy(maxRetries, retryableExceptions, true));

    // Default retry listener will not perform any action on Client Errors (such as
    // Unauthorized)
    // but will prevent retries when the request fails due to timeout or service
    // unavailable
    retryTemplate.registerListener(new DefaultRetryListener(false));

    // This custom listener resets the service verification token if the request is
    // rejected as
    // UNAUTHORIZED
    retryTemplate.registerListener(new ResetUnauthorizedTokenRetryListener());

    return retryTemplate;
  }

  private RestTemplate serviceTokenInjectedRestTemplate() {

    val restTemplate = new RestTemplate();

    ClientHttpRequestInterceptor accessTokenAuthIntercept =
        (request, body, clientHttpRequestExecution) -> {
          request
              .getHeaders()
              .add("X-Service-Token", authZRestClient.getServiceVerificationToken());

          request.getHeaders().add("X-Service-Id", pcglAuthZConfig.getServiceId());
          return clientHttpRequestExecution.execute(request, body);
        };

    restTemplate.getInterceptors().add(accessTokenAuthIntercept);

    return restTemplate;
  }
}
