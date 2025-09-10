package bio.overture.song.server.security.authz;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AuthZUserClaims {

  private final String sub;
  private final List<String> editableStudies;
  private final List<String> readableStudies;
  private final List<String> groups;
}
