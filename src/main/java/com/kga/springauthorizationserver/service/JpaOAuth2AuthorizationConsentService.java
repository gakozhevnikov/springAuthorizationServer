package com.kga.springauthorizationserver.service;

import java.util.HashSet;
import java.util.Set;

import com.kga.springauthorizationserver.model.AuthorizationConsent;
import com.kga.springauthorizationserver.repository.AuthorizationConsentRepository;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


/** JpaOAuth2AuthorizationConsentService использует AuthorizationConsentRepository
 *  для сохранения AuthorizationConsent и сопоставляет с объектом домена OAuth2AuthorizationConsent и из него.*/

@Component
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {
    private final AuthorizationConsentRepository authorizationConsentRepository;
    private final RegisteredClientRepository registeredClientRepository;

    public JpaOAuth2AuthorizationConsentService(AuthorizationConsentRepository authorizationConsentRepository, RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(authorizationConsentRepository, "authorizationConsentRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationConsentRepository = authorizationConsentRepository;
        this.registeredClientRepository = registeredClientRepository;
    }
    /**Метод преобразует OAuth2AuthorizationConsent в AuthorizationConsent и преобразованный AuthorizationConsent
     * сохраняет в базе данных*/
    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.save(toEntity(authorizationConsent));
    }

    /**Удаляется из базы данных AuthorizationConsent по переменным registeredClientId() и principalName()*/
    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

    /**Осуществляется поиск по параметрам registeredClientId, principalName. Найденный AuthorizationConsent преобразуется
     * в OAuth2AuthorizationConsent методом {@link JpaOAuth2AuthorizationConsentService#toObject(AuthorizationConsent)}.
     * При отсутствии возвращается null*/
    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return this.authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
                registeredClientId, principalName).map(this::toObject).orElse(null);
    }

    /**Преобразование из AuthorizationConsent в OAuth2AuthorizationConsent.
     * Применяется в {@link JpaOAuth2AuthorizationConsentService#findById(String, String)} */
    private OAuth2AuthorizationConsent toObject(AuthorizationConsent authorizationConsent) {
        /*Проверяем есть ли в базе данных такой зарегистрированный клиент.
        Если нет выбрасываем исключение для завершения работы программы*/
        String registeredClientId = authorizationConsent.getRegisteredClientId();
        RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
        }
        /*При наличии зарегистрированного клиента проводим формирование OAuth2AuthorizationConsent*/
        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                registeredClientId, authorizationConsent.getPrincipalName());
        if (authorizationConsent.getAuthorities() != null) {
            for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsent.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }

        return builder.build();
    }

    /**Преобразование из OAuth2AuthorizationConsent в AuthorizationConsent.
     * Применяется в {@link JpaOAuth2AuthorizationConsentService#save(OAuth2AuthorizationConsent)}. */
    private AuthorizationConsent toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        AuthorizationConsent entity = new AuthorizationConsent();
        entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(authorizationConsent.getPrincipalName());

        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

        return entity;
    }
}


