package br.com.alg.gifoodauth.core;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtKeyStoreProperties jwtKeyStoreProperties;
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("checktoken")
                .secret(passwordEncoder.encode("123"))
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("write", "read")
                .accessTokenValiditySeconds(6 * 60 * 60) //6 dias
                .refreshTokenValiditySeconds(60 * 24 * 60 * 60)
                
                .and()
                   .withClient("foodanalytics")
                   .secret(passwordEncoder.encode(""))
                   .authorizedGrantTypes("authorization_code")
                   .scopes("write", "read")
                   .redirectUris("http://localhost:8085")
                   
                   //http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://aplicacao-cliente
                   
               .and()
                   .withClient("webadmin")
                   .authorizedGrantTypes("implicit")
                   .scopes("write", "read")
                   .redirectUris("http://aplicacao-cliente")
               
                   //http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente
                   
                .and()
                   .withClient("faturamentos")
                   .secret(passwordEncoder.encode("faturamento123"))
                   .authorizedGrantTypes("client_credentials")
                   .scopes("write", "read");
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()")
        .tokenKeyAccess("permitAll()")
        .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
        .userDetailsService(userDetailsService)
        .reuseRefreshTokens(true)
        .accessTokenConverter(jwtAccessTokenConverter())
        .approvalStore(approvalStore(endpoints.getTokenStore()))
        .tokenGranter(tokenGranter(endpoints));
    }
    
    private ApprovalStore approvalStore(TokenStore tokenStore) {
    	var approvalStore = new TokenApprovalStore();
    	approvalStore.setTokenStore(tokenStore);
    	return approvalStore;
    }
    
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
    	JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    	//jwtAccessTokenConverter.setSigningKey("89a7assd893564sdasd4as6a5sdasdasda1545ass4s");
    	var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
    	var keyStorePass = jwtKeyStoreProperties.getPassword();
    	var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
    	
    	var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
    	var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
    	
    	jwtAccessTokenConverter.setKeyPair(keyPair);
    	return jwtAccessTokenConverter;
    }
    
    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
}
