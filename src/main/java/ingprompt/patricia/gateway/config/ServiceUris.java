package ingprompt.patricia.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "gateway.services")
public class ServiceUris {

    // Values bind from gateway.services.* in application.yml (env var, else localhost
    // fallback declared there). Kept as a single source of truth — no defaults here.
    private String auth;
    private String parches;
    private String events;
    private String location;
    private String notification;

    private String locationWs;
    private String notificationWs;
}
