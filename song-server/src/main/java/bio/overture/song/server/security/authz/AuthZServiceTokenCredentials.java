package bio.overture.song.server.security.authz;

import lombok.Data;

@Data
public class AuthZServiceTokenCredentials {
  private final String serviceId;
  private final String serviceToken;
}
