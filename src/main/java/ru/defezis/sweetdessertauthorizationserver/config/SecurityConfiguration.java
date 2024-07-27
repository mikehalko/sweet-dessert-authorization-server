package ru.defezis.sweetdessertauthorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import ru.defezis.sweetdessertauthorizationserver.data.InMemoryUserDataService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static ru.defezis.sweetdessertauthorizationserver.enums.UserRole.ADMIN;
import static ru.defezis.sweetdessertauthorizationserver.enums.UserRole.USER;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(form -> {});

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDataService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ApplicationRunner dataLoader(UserDetailsService userRepository, PasswordEncoder encoder) {
        InMemoryUserDataService dataService = (InMemoryUserDataService) userRepository;
        return args -> {
            dataService.createUser(dataService.makeUser("admin", encoder.encode("admin"), ADMIN, USER));
            dataService.createUser(dataService.makeUser("user", encoder.encode("user"), USER));
        };
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("sweet-dessert")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:9090/login/oauth2/code/sweet-dessert")
                .scope("deleteDessert")
                .scope("writeDessert")
                .scope(OidcScopes.OPENID)
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }
    /*
    http://localhost:9000/oauth2/authorize?response_type=code&client_id=sweet-dessert&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/sweet-dessert&-scope=writeDessert+deleteDessert

    http://localhost:9000/oauth2/authorize?response_type=code&client_id=sweet-dessert&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/sweet-dessert&-scope=writeDessert+deleteDessert&continue
    */

    /**
     *
     * Сервер авторизации будет создавать токены JWT, эти токены должны включать подпись,
     * созданную с использованием веб-ключа JSON Web Key (JWK)1.
     * Поэтому нам понадобится несколько bean-компонентов для создания JWK.
     \* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    /**
     * JWKSource создает пары 2048-битных ключей RSA, которые будут использоваться для подписи токена.
     * Токен подписывается с использованием закрытого ключа.
     * Сервер ресурсов сможет проверить достоверность токена,
     * указанного в запросе, получив открытый ключ от сервера авторизации.
     *
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private static RSAKey generateRsaKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
