package com.example.config;

import javax.inject.Inject;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.EhCacheBasedTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import net.sf.ehcache.Cache;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final String CAS_SERVICE_HOST = "cas.service.host";
	private static final String CAS_SERVER_HOST = "cas.server.host";

	@Inject
	private Environment env;

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/static/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint());

		http.addFilterBefore(requestSingleLogoutFilter(), LogoutFilter.class);
		http.addFilterBefore(singleLogoutFilter(), CasAuthenticationFilter.class);

		http.addFilterBefore(casAuthenticationFilter(), BasicAuthenticationFilter.class);
		// http.addFilter(casAuthenticationFilter());

		http.logout().logoutSuccessUrl("/cas-logout.jsp");
		http.csrf().disable();

		// http.authorizeRequests().antMatchers("/").permitAll();
		http.authorizeRequests().antMatchers("/index.jsp").permitAll();
		http.authorizeRequests().antMatchers("/cas-logout.jsp").permitAll();
		http.authorizeRequests().antMatchers("/casfailed.jsp").permitAll();

		http.authorizeRequests().antMatchers("/user").hasAuthority(AuthoritiesConstants.USER);
		http.authorizeRequests().antMatchers("/admin").hasAuthority(AuthoritiesConstants.ADMIN);

		http.authorizeRequests().antMatchers("/user/**").hasAuthority(AuthoritiesConstants.USER);
		http.authorizeRequests().antMatchers("/admin/**").hasAuthority(AuthoritiesConstants.ADMIN);

		http.authorizeRequests().antMatchers("/metrics/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/health/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/trace/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/dump/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/shutdown/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/beans/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/configprops/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/info/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/autoconfig/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/env/**").hasAuthority(AuthoritiesConstants.ADMIN);
		http.authorizeRequests().antMatchers("/trace/**").hasAuthority(AuthoritiesConstants.ADMIN);
	}

	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
		CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
		casAuthenticationEntryPoint.setLoginUrl("http://" + env.getRequiredProperty(CAS_SERVER_HOST) + "/cas/login");
		casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
		return casAuthenticationEntryPoint;
	}

	@Inject
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(casAuthenticationProvider());
	}

	@Bean
	public CasAuthenticationProvider casAuthenticationProvider() {
		CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
		casAuthenticationProvider.setAuthenticationUserDetailsService(authenticationUserDetailsService());
		casAuthenticationProvider.setServiceProperties(serviceProperties());
		casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
		casAuthenticationProvider.setStatelessTicketCache(statelessTicketCache());
		casAuthenticationProvider.setKey("my_app_key");
		return casAuthenticationProvider;
	}

	@Bean
	public StatelessTicketCache statelessTicketCache() {
		EhCacheBasedTicketCache statelessTicketCache = new EhCacheBasedTicketCache();
		statelessTicketCache.setCache(ehcache());
		return statelessTicketCache;
	}

	@Bean
	public Cache ehcache() {
		Cache cache = new Cache("casTickets", 50, true, false, 3600, 900);
		cache.setCacheManager(new org.springframework.cache.ehcache.EhCacheManagerFactoryBean().getObject());
		return cache;
	}

	@Bean
	public Cas20ProxyTicketValidator cas20ServiceTicketValidator() {
		Cas20ProxyTicketValidator cas20ProxyTicketValidator = new Cas20ProxyTicketValidator(
				"http://" + env.getRequiredProperty(CAS_SERVER_HOST) + "/cas");
		cas20ProxyTicketValidator.setAcceptAnyProxy(true);
		cas20ProxyTicketValidator.setProxyCallbackUrl(
				"https://" + env.getRequiredProperty(CAS_SERVICE_HOST) + "/login/cas/proxyreceptor");
		cas20ProxyTicketValidator.setProxyGrantingTicketStorage(pgtStorage());
		return cas20ProxyTicketValidator;
	}

	@Bean
	public ProxyGrantingTicketStorageImpl pgtStorage() {
		return new ProxyGrantingTicketStorageImpl();
	}

	@Bean
	public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService() {
		return new UserDetailsServiceImpl();
	}

	@Bean
	public ServiceProperties serviceProperties() {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://" + env.getRequiredProperty(CAS_SERVICE_HOST) + "/login/cas");
		// serviceProperties.setSendRenew(false);
		serviceProperties.setAuthenticateAllArtifacts(true);
		return serviceProperties;
	}

	@Bean
	public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
		CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
		casAuthenticationFilter.setAuthenticationManager(authenticationManager());
		casAuthenticationFilter.setServiceProperties(serviceProperties());
		casAuthenticationFilter.setProxyGrantingTicketStorage(pgtStorage());
		casAuthenticationFilter.setProxyReceptorUrl("/login/cas/proxyreceptor");
		casAuthenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource());

		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
		failureHandler.setDefaultFailureUrl("/casfailed.jsp");

		casAuthenticationFilter.setAuthenticationFailureHandler(failureHandler);
		return casAuthenticationFilter;
	}

	public ServiceAuthenticationDetailsSource authenticationDetailsSource() {
		return new ServiceAuthenticationDetailsSource(serviceProperties());
	}

	public SingleSignOutFilter singleLogoutFilter() {
		SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
		singleSignOutFilter.setCasServerUrlPrefix("http://" + env.getRequiredProperty(CAS_SERVER_HOST) + "/cas");
		return singleSignOutFilter;
	}

	public LogoutFilter requestSingleLogoutFilter() {
		LogoutFilter logoutFilter = new LogoutFilter(
				"http://" + env.getRequiredProperty(CAS_SERVER_HOST) + "/cas/logout",
				new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl("/logout/cas");
		return logoutFilter;
	}

}
