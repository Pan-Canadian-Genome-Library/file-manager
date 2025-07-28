package bio.overture.song.server.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.List;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class AuthorizationService {

  @Value("${authz.host}")
  private String authZHost;

  @Value("${authz.admin.group}")
  private String adminGroupName;

  private final RestTemplate restTemplate = new RestTemplate();

  public UserDetails fetchUserDetails(String accessToken) {
    String url = authZHost + "/user/me";

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(accessToken);
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

    HttpEntity<Void> entity = new HttpEntity<>(headers);

    try {
      ResponseEntity<UserDetails> response =
          restTemplate.exchange(url, HttpMethod.GET, entity, UserDetails.class);

      return response.getBody();
    } catch (Exception e) {
      log.error("Failed to fetch user details from AuthZ", e);
      throw new RuntimeException("Failed to fetch user details from AuthZ", e);
    }
  }

  public boolean isAdmin(UserDetails userDetails) {
    if (userDetails.getGroups() == null) return false;

    return userDetails.getGroups().stream()
            .anyMatch(g -> adminGroupName.equalsIgnoreCase(g.getName()));
  }

  public boolean hasWriteAccessToStudy(UserDetails userDetails, String studyId) {
    if (isAdmin(userDetails)) return true;

    StudyAuthorizations studyAuth = userDetails.getStudyAuthorizations();
    if (studyAuth == null || studyAuth.getEditableStudies() == null) return false;

    return studyAuth.getEditableStudies().contains(studyId);
  }


  @Data
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class UserDetails {
    private UserInfo userinfo;

    @JsonProperty("study_authorizations")
    private StudyAuthorizations studyAuthorizations;

    private List<Group> groups;
  }

  @Data
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class UserInfo {
    @JsonProperty("pcgl_id")
    private String pcglId;

    @JsonProperty("site_admin")
    private boolean siteAdmin;

    @JsonProperty("site_curator")
    private boolean siteCurator;
  }

  @Data
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class StudyAuthorizations {
    @JsonProperty("editable_studies")
    private List<String> editableStudies;

    @JsonProperty("readable_studies")
    private List<String> readableStudies;
  }

  @Data
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Group {
    private String name;
    private String description;
    private int id;
  }
}
