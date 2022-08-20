package com.kga.springauthorizationserver.model;

import lombok.*;
import org.hibernate.Hibernate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.Instant;
import java.util.Objects;

/**Сущность, которая используется для сохранения информации, отображаемой из RegisteredClient объекта домена.
 * https://docs.spring.io/spring-authorization-server/docs/current/reference/html/core-model-components.html
 * */

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
public class Client {

    /**Идентификатор, который однозначно идентифицирует клиента.*/
    @Id
    private String id;
    /**Идентификатор клиента*/
    private String clientId;
    /**Время, в которое был выдан идентификатор клиента.*/
    private Instant clientIdIssuedAt;
    /**Секрет клиента. Значение должно быть закодировано с помощью PasswordEncoder от Spring Security*/
    private String clientSecret;
    /**Время истечения срока действия клиентского секрета*/
    private Instant clientSecretExpiresAt;
    /**Описательное имя, используемое для клиента. Имя может использоваться в определенных сценариях, например, при отображении имени клиента на странице согласия.*/
    private String clientName;
    /**Метод(ы) аутентификации, которые может использовать клиент. Поддерживаемые значения следующие: client_secret_basic,
     * client_secret_post, private_key_jwt, client_secret_jwt и none (общедоступные клиенты).*/
    @Column(length = 1000)
    private String clientAuthenticationMethods;
    /** тип(ы) предоставления авторизации, который может использовать клиент. Поддерживаемые значения: authorization_code, client_credentials и refresh_token.*/
    @Column(length = 1000)
    private String authorizationGrantTypes;
    /**Зарегистрированный URI(ы) перенаправления, который клиент может использовать в потоках на основе перенаправления - например, authorization_code grant.
     * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
     * Конечная точка перенаправления
     * После завершения взаимодействия с владельцем ресурса
     * сервер авторизации направляет пользовательский агент владельца ресурса обратно
     * клиенту. Сервер авторизации перенаправляет пользовательский агент на
     * конечную точку перенаправления клиента, ранее установленную с сервером
     * авторизации во время процесса регистрации клиента или при
     * выполнении запроса авторизации.*/
    @Column(length = 1000)
    private String redirectUris;
    /**Область (области), которую клиенту разрешено запрашивать*/
    @Column(length = 1000)
    private String scopes;
    /**Пользовательские настройки для клиента – например, требовать PKCE (https://datatracker.ietf.org/doc/html/rfc7636), требовать согласия на авторизацию и другие.*/
    @Column(length = 2000)
    private String clientSettings;
    /**Пользовательские настройки для токенов OAuth2, выданных клиенту, например, время действия токена доступа/обновления,
     * повторное использование токенов обновления и другие.*/
    @Column(length = 2000)
    private String tokenSettings;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        Client client = (Client) o;
        return id != null && Objects.equals(id, client.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
