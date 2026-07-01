package ingprompt.patricia.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter, Ordered {
    public static final String USER_ID_HEADER = "X-User-Id";

    private static final String BEARER_PREFIX = "Bearer ";
    private static final List<String> PUBLIC_PATH_PREFIXES = List.of(
            "/auth/",
            "/actuator/health",
            "/actuator/info");

    private final JwtService jwtService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // CORS preflight must not require auth.
        if (request.getMethod() != null && "OPTIONS".equalsIgnoreCase(request.getMethod().name())) {
            return chain.filter(stripUserId(exchange));
        }

        String path = request.getPath().value();
        if (isPublic(path)) {
            return chain.filter(stripUserId(exchange));
        }

        String token = bearerToken(request);
        if (token == null) {
            return unauthorized(exchange, "Missing bearer token");
        }

        try {
            Claims claims = jwtService.validateAndExtract(token);
            String userId = claims.getSubject();
            if (userId == null || userId.isBlank()) {
                return unauthorized(exchange, "Token has no subject");
            }
            ServerWebExchange authenticated = exchange.mutate()
                    .request(r -> r.headers(h -> h.remove(USER_ID_HEADER))
                            .header(USER_ID_HEADER, userId))
                    .build();
            return chain.filter(authenticated);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT rejected on {}: {}", path, e.getMessage());
            return unauthorized(exchange, "Invalid or expired token");
        }
    }

    private boolean isPublic(String path) {
        return PUBLIC_PATH_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private String bearerToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /** Removes any inbound X-User-Id so clients can never forge identity. */
    private ServerWebExchange stripUserId(ServerWebExchange exchange) {
        return exchange.mutate()
                .request(r -> r.headers(h -> h.remove(USER_ID_HEADER)))
                .build();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String reason) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        log.debug("401 on {}: {}", exchange.getRequest().getPath().value(), reason);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
