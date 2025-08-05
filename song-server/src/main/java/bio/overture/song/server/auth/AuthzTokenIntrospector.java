package bio.overture.song.server.auth;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Component
public class AuthzTokenIntrospector implements OpaqueTokenIntrospector {

  private final RestTemplate restTemplate = new RestTemplate();

  @Value("${authz.host}")
  private String authzHost;

  @Override
  public OAuth2AuthenticatedPrincipal introspect(String token)
      throws OAuth2AuthenticationException {
    String url = UriComponentsBuilder.fromHttpUrl(authzHost).path("/user/me").toUriString();

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);

    HttpEntity<Void> request = new HttpEntity<>(headers);

    try {
      ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
      Map<String, Object> userDetails = response.getBody();

      Map<String, Object> claims = extractClaims(userDetails);
      List<GrantedAuthority> authorities = extractAuthorities(claims);

      return new DefaultOAuth2AuthenticatedPrincipal(claims, authorities);

    } catch (Exception e) {
      log.error("Failed to introspect token with AuthZ", e);
      throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token"), e.getMessage());
    }
  }

  private Map<String, Object> extractClaims(Map<String, Object> userDetails) {
    Map<String, Object> userinfo = (Map<String, Object>) userDetails.get("userinfo");
    Map<String, Object> studyAuths = (Map<String, Object>) userDetails.get("study_authorizations");
    List<Map<String, Object>> groups = (List<Map<String, Object>>) userDetails.get("groups");

    Map<String, Object> claims =
        Map.of(
            "sub", userinfo.get("pcgl_id"),
            "email", ((List<Map<String, Object>>) userinfo.get("emails")).get(0).get("address"),
            "editable_studies", studyAuths.get("editable_studies"),
            "readable_studies", studyAuths.get("readable_studies"),
            "groups",
                groups.stream().map(g -> g.get("name").toString()).collect(Collectors.toList()));

    return claims;
  }

  private List<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
    List<String> groups = (List<String>) claims.getOrDefault("groups", List.of());
    return groups.stream()
        .map(group -> new SimpleGrantedAuthority("ROLE_" + group))
        .collect(Collectors.toList());
  }
}
