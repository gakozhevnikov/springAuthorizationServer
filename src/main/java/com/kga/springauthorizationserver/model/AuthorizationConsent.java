package com.kga.springauthorizationserver.model;

import lombok.*;
import org.hibernate.Hibernate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import java.io.Serializable;
import java.util.Objects;

/**Согласие на авторизацию. Сущность, которая используется для сохранения информации, отображаемой из OAuth2AuthorizationConsent объекта домена.
 * Далее перевод из {@link org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent}.
 * Представление "согласия" OAuth 2.0 на запрос авторизации, который содержит состояние, связанное с набором полномочий,
 * предоставленных клиенту владельцем ресурса.
 * При авторизации доступа для данного клиента владелец ресурса может предоставить только подмножество полномочий,
 * запрошенных клиентом. Типичным вариантом использования является поток authorization_code, в котором клиент
 * запрашивает набор областей. Затем владелец ресурса выбирает, какие области они предоставляют клиенту.
 * */

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
/*@IdClass. Задает составной класс первичного ключа, который сопоставляется нескольким полям или свойствам объекта.
Имена полей или свойств в классе первичного ключа и полей или свойств первичного ключа объекта должны соответствовать,
а их типы должны быть одинаковыми.*/
@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
public class AuthorizationConsent {
    @Id
    private String registeredClientId;
    @Id
    private String principalName;
    @Column(length = 1000)
    private String authorities;

    public static class AuthorizationConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;

        public String getRegisteredClientId() {
            return registeredClientId;
        }

        public void setRegisteredClientId(String registeredClientId) {
            this.registeredClientId = registeredClientId;
        }

        public String getPrincipalName() {
            return principalName;
        }

        public void setPrincipalName(String principalName) {
            this.principalName = principalName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }

}


