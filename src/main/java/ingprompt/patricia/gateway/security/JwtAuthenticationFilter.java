package ingprompt.patricia.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import ingprompt.patricia.gateway.config.GatewaySecurityProperties;
import ingprompt.patricia.gateway.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Filtro global de autenticación del Gateway.
 *
 * Valida localmente (misma firma HS256 y {@code JWT_SECRET} que el Auth
 * Backend) el token del header {@code Authorization: Bearer <token>} de
 * TODA petición que no esté en la lista de rutas públicas.
 *
 * Si el token es válido, el Gateway inyecta la identidad del usuario en
 * headers internos ({@code X-User-Id}, {@code X-User-Email}, {@code X-User-Roles})
 * antes de rutear al microservicio correspondiente. Los microservicios
 * internos NO necesitan validar el JWT de nuevo: confían en estos headers
 * porque solo el Gateway puede alcanzarlos (red interna).
 *
 * Por eso mismo, los microservicios downstream deben:
 *   1) No estar expuestos directamente fuera de la red interna.
 *   2) Ignorar/sobrescribir cualquier X-User-* que venga del cliente final,
 *      quedándose solo con el que puso el Gateway (aquí ya se limpia el
 *      header entrante antes de fijar el propio, ver {@link #mutateWithIdentity}).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_EMAIL = "X-User-Email";
    private static final String HEADER_USER_ROLES = "X-User-Roles";

    private final JwtProperties jwtProperties;
    private final GatewaySecurityProperties securityProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Preflight CORS y rutas públicas pasan sin validar JWT
        if (request.getMethod() != null && request.getMethod().name().equals("OPTIONS")
                || isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(AUTH_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "missing_token", "Falta el header Authorization: Bearer <token>");
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .clockSkewSeconds(0)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (claims.getSubject() == null) {
                return unauthorized(exchange, "invalid_token", "Token sin claim 'sub'");
            }

            ServerWebExchange mutatedExchange = mutateWithIdentity(exchange, claims);
            return chain.filter(mutatedExchange);

        } catch (ExpiredJwtException e) {
            return unauthorized(exchange, "expired_token", "El token expiró");
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT inválido: {}", e.getMessage());
            return unauthorized(exchange, "invalid_token", "Token inválido");
        }
    }

    /**
     * Reescribe la petición: elimina cualquier X-User-* que haya mandado
     * el cliente (para que nadie pueda suplantar identidad saltándose el
     * Gateway) y fija los headers con los datos extraídos del JWT ya
     * validado.
     */
    private ServerWebExchange mutateWithIdentity(ServerWebExchange exchange, Claims claims) {
        String email = claims.get("email", String.class);
        List<?> roles = claims.get("roles", List.class);
        String rolesHeader = roles == null
                ? ""
                : String.join(",", roles.stream().map(String::valueOf).toList());

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(HEADER_USER_ID);
                    headers.remove(HEADER_USER_EMAIL);
                    headers.remove(HEADER_USER_ROLES);
                    headers.set(HEADER_USER_ID, claims.getSubject());
                    if (email != null) {
                        headers.set(HEADER_USER_EMAIL, email);
                    }
                    headers.set(HEADER_USER_ROLES, rolesHeader);
                })
                .build();

        return exchange.mutate().request(mutatedRequest).build();
    }

    private boolean isPublicPath(String path) {
        return securityProperties.getPublicPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String reason, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = Map.of(
                "error", reason,
                "message", message
        );

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (Exception e) {
            bytes = ("{\"error\":\"" + reason + "\"}").getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Debe ejecutarse antes de los filtros de ruteo del Gateway.
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}
