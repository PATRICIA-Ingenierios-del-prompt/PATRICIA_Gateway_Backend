package ingprompt.patricia.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración del secreto JWT usado para validar los tokens emitidos
 * por el Auth Backend. Debe ser el MISMO valor (env var {@code JWT_SECRET})
 * configurado en el microservicio de autenticación, ya que el Gateway
 * valida la firma localmente en lugar de llamar a /auth/validate en
 * cada petición.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secret;
}
