package bio.overture.song.server.auth;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Service;

@Service
public class AuthZAuthorizationService {

  private final AuthzTokenIntrospector introspector;

  @Value("${authz.admin.group}")
  private String ADMIN_GROUP;

  public AuthZAuthorizationService(AuthzTokenIntrospector introspector) {
    this.introspector = introspector;
  }

  private OAuth2AuthenticatedPrincipal getPrincipalFromAuth(Authentication authentication) {
    OAuth2Token token = (OAuth2Token) authentication.getCredentials();
    return introspector.introspect(token.getTokenValue());
  }

  public boolean isAdmin(Authentication authentication) {
    OAuth2AuthenticatedPrincipal principal = getPrincipalFromAuth(authentication);
    List<String> groups = principal.getAttribute("groups");
    return groups != null && groups.contains(ADMIN_GROUP);
  }

  public boolean canEditStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    OAuth2AuthenticatedPrincipal principal = getPrincipalFromAuth(authentication);
    List<String> editableStudies = principal.getAttribute("editable_studies");
    return editableStudies != null && editableStudies.contains(studyId);
  }

  public boolean canReadStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    OAuth2AuthenticatedPrincipal principal = getPrincipalFromAuth(authentication);
    List<String> readableStudies = principal.getAttribute("readable_studies");
    return readableStudies != null && readableStudies.contains(studyId);
  }
}
