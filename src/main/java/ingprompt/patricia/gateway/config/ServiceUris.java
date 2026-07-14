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
    private String auth;
    private String users;
    private String parches;
    private String events;
    private String location;
    private String notification;
    private String board;
    private String parques;
    private String matching;
    private String communication;

    private String locationWs;
    private String notificationWs;
    private String boardWs;
    private String parquesWs;
    private String communicationWs;
}
