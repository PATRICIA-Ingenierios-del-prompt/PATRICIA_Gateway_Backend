package ingprompt.patricia.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder, ServiceUris uris) {
        return builder.routes()
                // --- Auth MS: /auth/login is public, the rest still go through the gateway ---
                .route("auth", r -> r.path("/auth/**").uri(uris.getAuth()))

                // --- REST microservices ---
                .route("users", r -> r.path("/api/v1/usuarios/**", "/api/v1/intereses/**").uri(uris.getUsers()))
                .route("parches", r -> r.path("/api/parches/**", "/api/invites/**").uri(uris.getParches()))
                .route("events", r -> r.path("/api/events/**").uri(uris.getEvents()))
                .route("location", r -> r.path("/api/locations/**").uri(uris.getLocation()))
                .route("notifications", r -> r.path("/api/notifications/**").uri(uris.getNotification()))
                .route("board", r -> r.path("/api/boards/**").uri(uris.getBoard()))
                .route("parques", r -> r.path("/api/games/**").uri(uris.getParques()))
                // JWT propio validado por Matching (MatchingController + su
                // JwtAuthenticationFilter interno); el Gateway solo enruta.
                .route("matching", r -> r.path("/matching/**").uri(uris.getMatching()))
                .route("communication", r -> r.path("/api/chat/**", "/api/voice/**").uri(uris.getCommunication()))

                // --- STOMP WebSocket tunnels (upgrade handshake carries the JWT) ---
                .route("location-ws", r -> r.path("/ws/geo/**").uri(uris.getLocationWs()))
                .route("notifications-ws", r -> r.path("/ws/notifications/**").uri(uris.getNotificationWs()))
                .route("board-ws", r -> r.path("/ws/board/**").uri(uris.getBoardWs()))
                .route("parques-ws", r -> r.path("/parques-ws/**").uri(uris.getParquesWs()))
                // Chat/voice STOMP (native WS): the JWT rides ?access_token= on the
                // upgrade, same mechanism as /ws/geo (JwtAuthenticationFilter).
                .route("communication-ws", r -> r.path("/ws-stomp/**").uri(uris.getCommunicationWs()))

                .build();
    }
}
