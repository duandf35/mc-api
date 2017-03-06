package com.mc.config;

import com.mc.security.login.LoginAuthenticationFailureHandler;
import com.mc.security.login.LoginAuthenticationProvider;
import com.mc.security.login.LoginAuthenticationSuccessHandler;
import com.mc.security.login.LoginProcessingFilter;
import com.mc.security.token.JwtAuthenticationProvider;
import com.mc.security.token.JwtAuthenticationRequestMatcher;
import com.mc.security.token.JwtTokenAuthenticationProcessingFilter;
import com.mc.security.user.DbUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.List;

/**
 * Note:
 * 1. Multiple WebSecurityConfigurerAdapters must have different @Order, and each adapter will create its own filter chain !
 *
 * 2. Customizing AuthenticationManager requires expose a bean via authenticationManagerBean().
 *
 * 3. Exposing AuthenticationManager bean and inject it via constructor (field injection is ok) in the same class causes dependency cycle.
 *
 * 4. The front-end should always hit the FORM_BASED_LOGIN_ENTRY_POINT for authentication.
 *
 * 5. How does the Spring security filter chain work:
 * http://stackoverflow.com/questions/41480102/how-spring-security-filter-chain-works
 *
 * @author Wenyu
 * @since 2/11/17
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";

    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";

    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";

    private LoginAuthenticationProvider loginAuthenticationProvider;

    private LoginAuthenticationSuccessHandler loginAuthenticationSuccessHandler;

    private LoginAuthenticationFailureHandler loginAuthenticationFailureHandler;

    private JwtAuthenticationProvider jwtAuthenticationProvider;

    private DbUserDetailsService dbUserDetailsService;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public WebSecurityConfig(LoginAuthenticationProvider loginAuthenticationProvider,
                             LoginAuthenticationSuccessHandler loginAuthenticationSuccessHandler,
                             LoginAuthenticationFailureHandler loginAuthenticationFailureHandler,
                             JwtAuthenticationProvider jwtAuthenticationProvider,
                             DbUserDetailsService dbUserDetailsService) {
        this.loginAuthenticationProvider = loginAuthenticationProvider;
        this.loginAuthenticationSuccessHandler = loginAuthenticationSuccessHandler;
        this.loginAuthenticationFailureHandler = loginAuthenticationFailureHandler;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
        this.dbUserDetailsService = dbUserDetailsService;
    }

    @Bean
    protected LoginProcessingFilter loginProcessingFilter() throws Exception {
        LoginProcessingFilter filter = new LoginProcessingFilter(FORM_BASED_LOGIN_ENTRY_POINT, loginAuthenticationSuccessHandler, loginAuthenticationFailureHandler);

        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }

    @Bean
    protected JwtTokenAuthenticationProcessingFilter jwtTokenAuthenticationProcessingFilter() throws Exception {
        List<String> pathToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        JwtAuthenticationRequestMatcher requestMatcher = new JwtAuthenticationRequestMatcher(pathToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);

        JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(loginAuthenticationFailureHandler, requestMatcher);

        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.authenticationProvider(loginAuthenticationProvider);
        builder.authenticationProvider(jwtAuthenticationProvider);
        builder.userDetailsService(dbUserDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // jwt doesn't need csrf protection
                .exceptionHandling()
                // the default authentication entry point is Http403ForbiddenEntryPoint
                // .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // disable session
                .and()
                .authorizeRequests()
                .antMatchers(FORM_BASED_LOGIN_ENTRY_POINT).permitAll()
                .antMatchers(TOKEN_REFRESH_ENTRY_POINT).permitAll()
                .and()
                .authorizeRequests()
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated()
                .and()
                .addFilterBefore(loginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
