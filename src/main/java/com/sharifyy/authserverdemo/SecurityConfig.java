package com.sharifyy.authserverdemo;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class SecurityConfig {


	@Bean
	@Order(1)
	public SecurityFilterChain authFilterChain(HttpSecurity httpSecurity) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());

		httpSecurity
			.exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		return httpSecurity.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(requestMatcherRegistry ->
				requestMatcherRegistry.requestMatchers("/login", "/error", "/logo.png").permitAll()
					.anyRequest().authenticated())
			.formLogin(c->c.loginPage("/login"))
			.oauth2Login(c->c.loginPage("/login")
				.successHandler(authenticationSuccessHandler()));

		return httpSecurity.build();
	}

	private AuthenticationSuccessHandler authenticationSuccessHandler() {
		var successHandler = new FederatedIdentityAuthenticationSuccessHandler();
		successHandler.setOAuth2UserHandler(new UserRepositoryOAuth2UserHandler());
		return successHandler;
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient client1 = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("javatalks-web-app")
//			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri("http://127.0.0.1:8080/login/oauth2/code/java-talks")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.EMAIL)
			.clientSettings(ClientSettings.builder()
				.requireAuthorizationConsent(true)
				.requireProofKey(true)
				.build()
			)
			.tokenSettings(TokenSettings.builder()
				.accessTokenTimeToLive(Duration.ofMinutes(5))
				.refreshTokenTimeToLive(Duration.ofMinutes(15))
				.authorizationCodeTimeToLive(Duration.ofSeconds(60))
				.build())
			.build();

		RegisteredClient client2 = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("resource-server")
			.clientSecret("secret2")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.build();

		return new InMemoryRegisteredClientRepository(client1,client2);
	}

	@Bean
	public UserDetailsService userDetailsService(){
		UserDetails user1 = User.withUsername("sharifyy").password("secret").authorities("developer").build();
		return new InMemoryUserDetailsManager(user1);
	}

	@Bean
	public PasswordEncoder passwordEncoder(){
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			context.getClaims().claim("claim_demonstration", "whatever");
			context.getClaims().claim("roles", context.getPrincipal().getAuthorities().stream().map(Object::toString).toList());
		};
	}

	@Bean
	JWKSource<SecurityContext> jwkSource(
		@Value("${jwt.key.id}") String keyId,
		@Value("${jwt.key.public}") RSAPublicKey publicKey,
		@Value("${jwt.key.private}") RSAPrivateKey privateKey
	){
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
			.privateKey(privateKey)
			.keyID(keyId)
			.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}
}
