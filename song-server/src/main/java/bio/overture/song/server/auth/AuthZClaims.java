package bio.overture.song.server.auth;

import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthZClaims {
  private final String sub;
  private final List<String> editableStudies;
  private final List<String> readableStudies;
  private final List<String> groups;
}
