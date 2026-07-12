package ingprompt.patricia.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "security")
public class GatewaySecurityProperties {
    private List<String> publicPaths = new java.util.ArrayList<>(List.of(
            "/auth/**",
            "/actuator/health",
            "/actuator/info"
    ));
}
