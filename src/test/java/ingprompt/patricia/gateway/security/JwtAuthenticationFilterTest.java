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
