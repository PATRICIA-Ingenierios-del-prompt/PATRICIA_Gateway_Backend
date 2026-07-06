package ingprompt.patricia.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Rutas que el Gateway deja pasar SIN exigir JWT.
 * Configurable vía {@code security.public-paths} en application.yml,
 * usando patrones Ant (soporta {@code **} y {@code *}).
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "security")
public class GatewaySecurityProperties {

    /**
     * Rutas públicas por defecto: login/OTP/refresh/validate del auth-service,
     * documentación y health checks.
     */
    private List<String> publicPaths = List.of(
            "/auth/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/v3/api-docs/**",
            "/actuator/health"
    );
}
