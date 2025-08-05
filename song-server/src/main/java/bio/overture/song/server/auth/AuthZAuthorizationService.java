package bio.overture.song.server.auth;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;

@Service
@Profile("secure")
public class AuthZAuthorizationService {

  @Value("${authz.admin.group}")
  private String ADMIN_GROUP;

  private OAuth2AuthenticatedPrincipal getPrincipalFromAuth(Authentication authentication) {
    if (authentication.getPrincipal() instanceof OAuth2AuthenticatedPrincipal) {
      return (OAuth2AuthenticatedPrincipal) authentication.getPrincipal();
    }
    return null;
  }

  public boolean isAdmin(Authentication authentication) {
    OAuth2AuthenticatedPrincipal principal = getPrincipalFromAuth(authentication);
    if (principal == null) return false;
    List<String> groups = principal.getAttribute("groups");
    return groups != null && groups.contains(ADMIN_GROUP);
  }

  public boolean canEditStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    OAuth2AuthenticatedPrincipal principal = getPrincipalFromAuth(authentication);
    if (principal == null) return false;
    List<String> editableStudies = principal.getAttribute("editable_studies");
    return editableStudies != null && editableStudies.contains(studyId);
  }

  public boolean canReadStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    OAuth2AuthenticatedPrincipal principal = getPrincipalFromAuth(authentication);
    if (principal == null) return false;
    List<String> readableStudies = principal.getAttribute("readable_studies");
    return readableStudies != null && readableStudies.contains(studyId);
  }
}
