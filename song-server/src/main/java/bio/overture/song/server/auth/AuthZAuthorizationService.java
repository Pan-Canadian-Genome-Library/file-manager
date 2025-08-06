package bio.overture.song.server.auth;

import java.util.List;
import java.util.Optional;
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

  private Optional<OAuth2AuthenticatedPrincipal> getPrincipalFromAuth(
      Authentication authentication) {
    if (authentication.getPrincipal() instanceof OAuth2AuthenticatedPrincipal) {
      return Optional.ofNullable((OAuth2AuthenticatedPrincipal) authentication.getPrincipal());
    }
    return Optional.empty();
  }

  public boolean isAdmin(Authentication authentication) {
    Optional<OAuth2AuthenticatedPrincipal> principalOptional = getPrincipalFromAuth(authentication);
    if (principalOptional.isEmpty()) return false;
    OAuth2AuthenticatedPrincipal principal = principalOptional.get();
    List<String> groups = principal.getAttribute("groups");
    return groups != null && groups.contains(ADMIN_GROUP);
  }

  public boolean canEditStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    Optional<OAuth2AuthenticatedPrincipal> principalOptional = getPrincipalFromAuth(authentication);
    if (principalOptional.isEmpty()) return false;
    OAuth2AuthenticatedPrincipal principal = principalOptional.get();
    List<String> editableStudies = principal.getAttribute("editable_studies");
    return editableStudies != null && editableStudies.contains(studyId);
  }

  public boolean canReadStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    Optional<OAuth2AuthenticatedPrincipal> principalOptional = getPrincipalFromAuth(authentication);
    if (principalOptional.isEmpty()) return false;
    OAuth2AuthenticatedPrincipal principal = principalOptional.get();
    List<String> readableStudies = principal.getAttribute("readable_studies");
    return readableStudies != null && readableStudies.contains(studyId);
  }
}
