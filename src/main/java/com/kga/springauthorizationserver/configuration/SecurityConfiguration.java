package com.kga.springauthorizationserver.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class SecurityConfiguration {

    @Bean//Цепочка фильтров Spring Security для конечных точек протокола.
    @Order(10)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                // Перенаправляем на страницу входа, если не авторизованы в конечной точке авторизации
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint( new LoginUrlAuthenticationEntryPoint("/login")));
        return http.build();
    }

    @Bean//Цепочка фильтров Spring Security для аутентификации (кто ты?)
    @Order(20)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        //Здесь мы вызываем authorizeRequests.anyRequest().authenticated(), чтобы требовать аутентификацию для всех запросов.
        // Мы также предоставляем аутентификацию на основе форм, вызывая метод formLogin(Customizer.withDefaults()) .
        http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // Форма входа обрабатывает перенаправление на страницу входа с цепочки фильтров сервера авторизации
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**3. Экземпляр UserDetailsService для получения пользователей для аутентификации.*/
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails userDetailsService = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetailsService);
    }

    /**5. Экземпляр com.nimbusds.jose.jwk.source.JWKSource для подписи access tokens.**/
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey(); //Этот класс представляет собой простой держатель для пары ключей (открытый ключ и закрытый ключ). Он не обеспечивает никакой безопасности и при инициализации должен рассматриваться как Закрытый ключ.
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();// В generateRsaKey() мы указали в KeyPairGenerator.getInstance("RSA") RSA поэтому в дальнейшем оперируем RSAkey
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**6. Экземпляр java.security.KeyPair с ключами, сгенерированными при запуске, использовался для создания JWKSource вышеуказанного (5).*/
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //Возвращает объект KeyPairGenerator, который генерирует пары открытых/закрытых ключей для указанного алгоритма. Этот метод просматривает список зарегистрированных поставщиков услуг безопасности, начиная с наиболее предпочтительного Поставщика. Возвращается новый объект KeyPairGenerator, инкапсулирующий реализацию KeyPairGeneratorSpi от первого поставщика, поддерживающего указанный алгоритм. Обратите внимание, что список зарегистрированных поставщиков может быть получен с помощью метода Security.getProviders()
            keyPairGenerator.initialize(2048); //Инициализирует генератор пары ключей для определенного размера ключа, используя набор параметров по умолчанию и реализацию SecureRandom установленного поставщика с наивысшим приоритетом в качестве источника случайности. (Если ни один из установленных поставщиков не предоставляет реализацию SecureRandom, используется системный источник случайности.) Параметры:            keysize – размер ключа. Это специфичная для алгоритма метрика, такая как длина модуля, указываемая в количестве битов.
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**7. Экземпляр ProviderSettings для настройки Spring Authorization Server.
     * Средство для настройки параметров конфигурации поставщика.
     * За исключением ключа подписи, каждый сервер авторизации также должен иметь уникальный URL-адрес издателя.*/
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();//Конфигурация по умолчанию
    }


}
