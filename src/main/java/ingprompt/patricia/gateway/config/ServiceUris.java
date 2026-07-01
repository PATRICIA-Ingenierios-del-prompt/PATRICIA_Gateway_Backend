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

    private String auth = "http://localhost:8081";
    private String parches = "http://localhost:8083";
    private String events = "http://localhost:8087";
    private String location = "http://localhost:8089";
    private String notification = "http://localhost:8091";

    private String locationWs = "ws://localhost:8089";
    private String notificationWs = "ws://localhost:8091";
}
