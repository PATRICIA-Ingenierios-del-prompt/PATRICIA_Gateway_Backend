package ingprompt.patricia.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import ingprompt.patricia.gateway.config.GatewaySecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String WS_TOKEN_PARAM = "access_token";

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_EMAIL = "X-User-Email";
    private static final String HEADER_USER_ROLES = "X-User-Roles";

    private final JwtService jwtService;
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

        String headerToken = bearerToken(request);
        String queryToken = (headerToken == null && isWebSocketUpgrade(request))
                ? trimToNull(request.getQueryParams().getFirst(WS_TOKEN_PARAM))
                : null;
        String token = headerToken != null ? headerToken : queryToken;
        final boolean stripQueryToken = queryToken != null;

        if (token == null) {
            return unauthorized(exchange, "missing_token", "Falta el header Authorization: Bearer <token>");
        }

        try {
            Claims claims = jwtService.validateAndExtract(token);

            if (claims.getSubject() == null) {
                return unauthorized(exchange, "invalid_token", "Token sin claim 'sub'");
            }

            ServerWebExchange mutatedExchange = mutateWithIdentity(exchange, claims, stripQueryToken);
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
     * Gateway), fija los headers con los datos extraídos del JWT ya
     * validado y, si el token venía por query param (WebSocket), lo quita
     * de la URI antes de reenviar.
     */
    private ServerWebExchange mutateWithIdentity(ServerWebExchange exchange, Claims claims, boolean stripQueryToken) {
        String email = claims.get("email", String.class);
        List<?> roles = claims.get("roles", List.class);
        String rolesHeader = roles == null
                ? ""
                : String.join(",", roles.stream().map(String::valueOf).toList());

        ServerHttpRequest.Builder builder = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(HEADER_USER_ID);
                    headers.remove(HEADER_USER_EMAIL);
                    headers.remove(HEADER_USER_ROLES);
                    headers.set(HEADER_USER_ID, claims.getSubject());
                    if (email != null) {
                        headers.set(HEADER_USER_EMAIL, email);
                    }
                    headers.set(HEADER_USER_ROLES, rolesHeader);
                });

        if (stripQueryToken) {
            builder.uri(stripAccessToken(exchange.getRequest().getURI()));
        }

        return exchange.mutate().request(builder.build()).build();
    }

    private boolean isPublicPath(String path) {
        return securityProperties.getPublicPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private String bearerToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return trimToNull(header.substring(BEARER_PREFIX.length()));
        }
        return null;
    }

    private boolean isWebSocketUpgrade(ServerHttpRequest request) {
        String upgrade = request.getHeaders().getFirst(HttpHeaders.UPGRADE);
        return upgrade != null && "websocket".equalsIgnoreCase(upgrade);
    }

    /** Devuelve la URI de la petición sin el query param {@code access_token}. */
    private URI stripAccessToken(URI uri) {
        return UriComponentsBuilder.fromUri(uri)
                .replaceQueryParam(WS_TOKEN_PARAM)
                .build(true)
                .toUri();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String reason, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");

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
        log.debug("401 on {}: {}", exchange.getRequest().getPath().value(), message);
        return response.writeWith(Mono.just(buffer));
    }

    /**
     * Debe ejecutarse antes de los filtros de ruteo del Gateway.
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}