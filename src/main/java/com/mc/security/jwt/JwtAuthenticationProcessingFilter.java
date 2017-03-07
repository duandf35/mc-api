package com.mc.security.jwt;

import com.mc.security.utils.WebUtils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Authenticate user against JWT access token.
 *
 * @author Wenyu
 * @since 2/18/17
 */
public class JwtAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationFailureHandler failureHandler;

    public JwtAuthenticationProcessingFilter(AuthenticationFailureHandler failureHandler, RequestMatcher matcher) {
        super(matcher);
        this.failureHandler = failureHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException
    {
        String rawJwtToken = WebUtils.extractTokenFromHeader(request);

        // invoke authentication provider
        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(rawJwtToken));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws AuthenticationException, IOException, ServletException
    {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authResult);

        SecurityContextHolder.setContext(context);

        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws AuthenticationException, IOException, ServletException
    {
        SecurityContextHolder.clearContext();

        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
