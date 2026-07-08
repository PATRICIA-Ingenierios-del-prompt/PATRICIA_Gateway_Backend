package ingprompt.patricia.gateway.security;

import ingprompt.patricia.gateway.config.GatewaySecurityProperties;
import ingprompt.patricia.gateway.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private static final String SECRET = "test-secret-key-with-at-least-32-bytes!!";

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret(SECRET);

        GatewaySecurityProperties securityProperties = new GatewaySecurityProperties();
        securityProperties.setPublicPaths(List.of("/auth/**"));

        filter = new JwtAuthenticationFilter(new JwtService(jwtProperties), securityProperties);
    }

    @Test
    void permitsPublicPathsWithoutToken() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/auth/login/microsoft").build()
        );
        GatewayFilterChain chain = mockChain();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void rejectsRequestWithoutToken() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1").build()
        );
        GatewayFilterChain chain = mockChain();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsInvalidToken() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1")
                        .header("Authorization", "Bearer not-a-real-token")
                        .build()
        );
        GatewayFilterChain chain = mockChain();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void acceptsValidTokenAndPropagatesIdentityHeaders() {
        String token = validToken();

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1")
                        .header("Authorization", "Bearer " + token)
                        // El cliente intenta suplantar identidad; debe ser sobrescrito
                        .header("X-User-Id", "attacker")
                        .build()
        );

        AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            captured.set(ex);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ServerWebExchange downstream = captured.get();
        assertThat(downstream).isNotNull();
        assertThat(downstream.getRequest().getHeaders().getFirst("X-User-Id")).isEqualTo("user-123");
        assertThat(downstream.getRequest().getHeaders().getFirst("X-User-Email")).isEqualTo("test@escuelaing.edu.co");
        assertThat(downstream.getRequest().getHeaders().getFirst("X-User-Roles")).isEqualTo("ESTUDIANTE,ADMIN");
    }

    @Test
    void permitsCorsPreflightWithoutToken() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.options("/api/parches").build()
        );
        GatewayFilterChain chain = mockChain();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void rejectsExpiredToken() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());
        Instant past = Instant.now().minusSeconds(3600);
        String expired = Jwts.builder()
                .subject("user-123")
                .issuedAt(Date.from(past))
                .expiration(Date.from(past.plusSeconds(60)))
                .signWith(key)
                .compact();

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1")
                        .header("Authorization", "Bearer " + expired)
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, mockChain())).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsTokenWithoutSubject() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());
        Instant now = Instant.now();
        String noSub = Jwts.builder()
                .claim("email", "test@escuelaing.edu.co")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(key)
                .compact();

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1")
                        .header("Authorization", "Bearer " + noSub)
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, mockChain())).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void websocketUpgrade_acceptsQueryTokenAndStripsItFromDownstreamUri() {
        String token = validToken();

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/ws/geo?access_token=" + token + "&foo=bar")
                        .header("Upgrade", "websocket")
                        .build()
        );

        AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            captured.set(ex);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ServerWebExchange downstream = captured.get();
        assertThat(downstream).isNotNull();
        assertThat(downstream.getRequest().getHeaders().getFirst("X-User-Id")).isEqualTo("user-123");
        // el token NO debe llegar al microservicio (ni a sus logs)
        assertThat(downstream.getRequest().getURI().toString()).doesNotContain("access_token");
        // el resto del query string se conserva
        assertThat(downstream.getRequest().getURI().getQuery()).contains("foo=bar");
    }

    @Test
    void queryToken_isIgnoredForPlainHttpRequests() {
        // Sin Upgrade: websocket, ?access_token= no es una credencial válida.
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1?access_token=" + validToken()).build()
        );

        StepVerifier.create(filter.filter(exchange, mockChain())).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void tokenWithoutRoles_yieldsEmptyRolesHeader() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());
        Instant now = Instant.now();
        String noRoles = Jwts.builder()
                .subject("user-123")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(key)
                .compact();

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/1")
                        .header("Authorization", "Bearer " + noRoles)
                        .build()
        );

        AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            captured.set(ex);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertThat(captured.get().getRequest().getHeaders().getFirst("X-User-Roles")).isEmpty();
        assertThat(captured.get().getRequest().getHeaders().getFirst("X-User-Email")).isNull();
    }

    @Test
    void runsAheadOfGatewayRouting() {
        assertThat(filter.getOrder())
                .isLessThan(org.springframework.core.Ordered.LOWEST_PRECEDENCE);
    }

    private String validToken() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());
        Instant now = Instant.now();
        return Jwts.builder()
                .subject("user-123")
                .claim("email", "test@escuelaing.edu.co")
                .claim("roles", List.of("ESTUDIANTE", "ADMIN"))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(key)
                .compact();
    }

    @SuppressWarnings("unchecked")
    private GatewayFilterChain mockChain() {
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.empty());
        return chain;
    }
}
