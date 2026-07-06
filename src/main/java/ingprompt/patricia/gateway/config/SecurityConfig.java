package ingprompt.patricia.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * La autenticación real la hace {@link ingprompt.patricia.gateway.security.JwtAuthenticationFilter}
 * como GlobalFilter de Spring Cloud Gateway (ver su Javadoc para el porqué).
 *
 * Esta clase solo desactiva los mecanismos por defecto de Spring Security
 * (login form, basic auth, csrf) y deja pasar todo a través de la cadena
 * de Security, ya que el filtro JWT se ejecuta antes, a nivel de Gateway,
 * y corta la petición con 401 si no está autorizada.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .cors(Customizer.withDefaults())
                .authorizeExchange(exchange -> exchange.anyExchange().permitAll())
                .build();
    }
}
