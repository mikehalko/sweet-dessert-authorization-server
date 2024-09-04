package ru.defezis.sweetdessertauthorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class ServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("sweet-dessert-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:9090/login/oauth2/code/sweet-dessert-client")
                .scope("writeDesserts")
                .scope("deleteDesserts")
                .scope("openid")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        final RSAKey rsaKey = generateRsa();
        final JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        final KeyPair keyPair = generateRsaKey();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}

/*
http://localhost:9000/oauth2/authorize?response_type=code&client_id=sweet-dessert-client&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/sweet-dessert-client&scope=writeDessert+deleteDessert

localhost:9000/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=authorization_code" -d"redirect_uri=http://127.0.0.1:9090/login/oauth2/code/sweet-dessert-client" -d"code=???" -u sweet-dessert-client:secret


{
	"access_token": "eyJraWQiOiJhMTBjOTJiYi1iMTUxLTRlM2ItYmZmMi1jYjAwM2E0MTZhNWEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6InN3ZWV0LWRlc3NlcnQtY2xpZW50IiwibmJmIjoxNzI0NDkzOTY4LCJzY29wZSI6WyJkZWxldGVEZXNzZXJ0Iiwid3JpdGVEZXNzZXJ0Il0sImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6OTAwMCIsImV4cCI6MTcyNDQ5NDI2OCwiaWF0IjoxNzI0NDkzOTY4fQ.pDQ3KB5Wl0OKJWE0p4lzglC9HWQZK4sEHhKJ74hTlinENP-iVgBZ0WpvQh9GcOZDHO5Zf1HR8EoFstk4zY1Lg84jObtineGKd1K30u3yGoZE9XK609gYRpydGulk211v7tP4B86W4bmgBPA9DJov36D8FzMnpk36BUiYo1at2uMzq7YPNDTZu2xqq1tV6PNw0vyMo3VHoBI8XNlCS8vmMtB7A5q-5onl0O-1wEB9EecDH-DLzT1HZmh6HEFBZf5AE862igNNyLcvxmIGvEfsg6SwuzlS9-IxhAs4tH-UchKnxgkpMaZ0s_M-6f9AMATZtEVaB7QAepNTUA-oiD4oZA",
	"refresh_token": "fQxTz-5STUD09ehqQ2ePn9rWtT46gsWKFHx--DQRdrczDVoJ9JIA5Y0fmCMPYtjjpxsEccRjrVJZVCjcg6O0vbnE2J3nijlSLfw9iazNjFsik_LmdGNw2rOaCBDLSeDh",
	"scope": "deleteDessert writeDessert",
	"token_type": "Bearer",
	"expires_in": 299
}

curl localhost:9000/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=refresh_token&refresh_token=fQxTz-5STUD09ehqQ2ePn9rWtT46gsWKFHx--DQRdrczDVoJ9JIA5Y0fmCMPYtjjpxsEccRjrVJZVCjcg6O0vbnE2J3nijlSLfw9iazNjFsik_LmdGNw2rOaCBDLSeDh" -u sweet-dessert-client:secret

 */