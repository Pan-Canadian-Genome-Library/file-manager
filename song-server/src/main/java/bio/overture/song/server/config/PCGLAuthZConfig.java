package bio.overture.song.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Data
@Profile("pcglauthz")
@Configuration
@ConfigurationProperties("auth.server.authz")
public class PCGLAuthZConfig {

  private String host;
  private String adminGroup;
  private String serviceId;
  private String serviceUUID;
}
