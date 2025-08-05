package bio.overture.song.server.utils;

import static lombok.AccessLevel.PRIVATE;

import bio.overture.song.server.security.KeycloakPermission;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import java.util.*;
import java.util.stream.Collectors;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@Slf4j
@NoArgsConstructor(access = PRIVATE)
public class Scopes {

  private static final String EXP = "exp";

  public static Set<String> extractGrantedScopes(Object source) {
    if (source instanceof Authentication) {
      Authentication authentication = (Authentication) source;
      if (authentication instanceof JwtAuthenticationToken) {
        return getJwtScopes((JwtAuthenticationToken) authentication);
      } else if (authentication instanceof BearerTokenAuthentication) {
        return getApiKeyScopes(((BearerTokenAuthentication) authentication).getPrincipal());
      }
      return Collections.emptySet();
    }
    return getApiKeyScopes(source);
  }

  public static Set<String> extractGrantedScopesFromRpt(List<KeycloakPermission> permissionList) {
    Set<String> grantedScopes = new HashSet<>();
    for (KeycloakPermission permission : permissionList) {
      if (permission.getScopes() != null) {
        for (String scope : permission.getScopes()) {
          String fullScope = permission.getRsname() + "." + scope;
          grantedScopes.add(fullScope);
        }
      }
    }
    return grantedScopes;
  }

  public static long extractExpiry(Map<String, ?> map) {
    Object exp = map.get(EXP);
    if (exp instanceof Integer) {
      return ((Integer) exp).longValue();
    } else if (exp instanceof Long) {
      return (Long) exp;
    }
    return 0L;
  }

  private static Set<String> getJwtScopes(JwtAuthenticationToken jwt) {
    Set<String> output = new HashSet<>();
    try {
      Object context = jwt.getToken().getClaim("context");
      if (context instanceof JSONObject) {
        Object scopes = ((JSONObject) context).get("scope");
        if (scopes instanceof JSONArray) {
          JSONArray scopeArray = (JSONArray) scopes;
          for (Object value : scopeArray) {
            if (value instanceof String) {
              output.add((String) value);
            }
          }
        }
      }
    } catch (ClassCastException e) {
      log.debug("Received JWT not structured as expected. No scopes found.");
    }
    return output;
  }


  private static Set<String> getApiKeyScopes(Object principal) {
    if (!(principal instanceof OAuth2AuthenticatedPrincipal)) {
      return Collections.emptySet();
    }

    OAuth2AuthenticatedPrincipal oAuth2Principal = (OAuth2AuthenticatedPrincipal) principal;

    Object scopeClaim = oAuth2Principal.getAttribute("scope");
    if (scopeClaim instanceof String) {
      String scopeString = (String) scopeClaim;
      return Arrays.stream(scopeString.split(" "))
          .filter(s -> !s.isBlank())
          .collect(Collectors.toSet());
    } else if (scopeClaim instanceof Collection) {
      Collection<?> scopeCollection = (Collection<?>) scopeClaim;
      return scopeCollection.stream()
          .map(Object::toString)
          .filter(s -> !s.isBlank())
          .collect(Collectors.toSet());
    }

    Object scpClaim = oAuth2Principal.getAttribute("scp");
    if (scpClaim instanceof Collection) {
      Collection<?> scpCollection = (Collection<?>) scpClaim;
      return scpCollection.stream()
          .map(Object::toString)
          .filter(s -> !s.isBlank())
          .collect(Collectors.toSet());
    }

    return Collections.emptySet();
  }
}
