package me.vinodh.sping_boot_sample.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import me.vinodh.sping_boot_sample.services.CustomUserDetailsService;
import me.vinodh.sping_boot_sample.services.JwtTokenService;

@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${client.app.url}")
	private String clientAppUrl;

	@Bean
	public PasswordEncoder passwordEncoder() {
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}

	@Autowired
	public CustomUserDetailsService customUserDetailsService;

	@Autowired
	private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

	@Autowired
	private CustomLoginSuccessHandler successHandler;

	@Autowired
	private JwtTokenService jwtTokenService;

	@Bean
	public SimpleUrlAuthenticationFailureHandler sendthruLoginFailureHandler() {
		return new SimpleUrlAuthenticationFailureHandler();
	}

	@Bean
	public HttpStatusReturningLogoutSuccessHandler logoutHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}

	@Bean
	public CorsFilter corsFilters() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(clientAppUrl));
		configuration.setAllowedMethods(Arrays.asList("POST", "GET", "OPTIONS", "DELETE"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(
				Arrays.asList("Content-Type", "Accept", "X-Requested-With", "remember-me", "authorization"));
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return new CorsFilter(source);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/webjars/**", "/css/**", "/images/**", "/js/**");

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		JwtFilter customFilter = new JwtFilter(this.jwtTokenService);
		http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);

		http.csrf().disable().authorizeRequests().antMatchers("/", "/login").permitAll().anyRequest().authenticated()
				.and().exceptionHandling().authenticationEntryPoint(restAuthenticationEntryPoint).and().formLogin()
				.successHandler(successHandler).failureHandler(sendthruLoginFailureHandler()).usernameParameter("email")
				.and().logout().logoutSuccessHandler(logoutHandler()).and()
				.addFilterBefore(corsFilters(), CsrfFilter.class);
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean(name = BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public RememberMeServices rememberMeServices() {
		return new TokenBasedRememberMeServices("remember-me", customUserDetailsService);
	}

}
