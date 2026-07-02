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
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter, Ordered {
    public static final String USER_ID_HEADER = "X-User-Id";

    private static final String BEARER_PREFIX = "Bearer ";

    private static final String WS_TOKEN_PARAM = "access_token";

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


        String headerToken = bearerToken(request);
        String queryToken = (headerToken == null && isWebSocketUpgrade(request))
                ? trimToNull(request.getQueryParams().getFirst(WS_TOKEN_PARAM))
                : null;
        String token = headerToken != null ? headerToken : queryToken;
        if (token == null) {
            return unauthorized(exchange, "Missing bearer token");
        }
        final boolean stripQueryToken = queryToken != null;

        try {
            Claims claims = jwtService.validateAndExtract(token);
            String userId = claims.getSubject();
            if (userId == null || userId.isBlank()) {
                return unauthorized(exchange, "Token has no subject");
            }
            ServerWebExchange authenticated = exchange.mutate()
                    .request(r -> {
                        r.headers(h -> h.remove(USER_ID_HEADER)).header(USER_ID_HEADER, userId);
                        if (stripQueryToken) {
                            r.uri(stripAccessToken(request.getURI()));
                        }
                    })
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
            return trimToNull(header.substring(BEARER_PREFIX.length()));
        }
        return null;
    }

    private boolean isWebSocketUpgrade(ServerHttpRequest request) {
        String upgrade = request.getHeaders().getFirst(HttpHeaders.UPGRADE);
        return upgrade != null && "websocket".equalsIgnoreCase(upgrade);
    }

    /** Returns the request URI with the {@code access_token} query-param removed. */
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
