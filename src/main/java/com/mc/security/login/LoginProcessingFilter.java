package com.mc.security.login;

import static com.mc.security.utils.WebUtils.AUTH_PASSWORD_KEY;
import static com.mc.security.utils.WebUtils.AUTH_USERNAME_KEY;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mc.security.utils.WebUtils;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * @author Wenyu
 * @since 2/18/17
 */
public class LoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthenticationSuccessHandler successHandler;

    private final AuthenticationFailureHandler failureHandler;

    public LoginProcessingFilter(String defaultProcessUrl, AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler) {
        super(defaultProcessUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    /**
     * Retrieve the user login information from request for constructing the Authentication object,
     * which suppose to be used by the AuthenticationProvider.
     *
     * Then invoke the AuthenticationProvide through the AuthenticationManager to do the actual
     * authentication.
     *
     * @param request http request
     * @param response http response
     * @return authenticate token if authenticate success
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException
    {
        if (!validate(request)) {
            throw new AuthenticationServiceException("Authentication method not support");
        }

        String username = request.getParameter(AUTH_USERNAME_KEY);
        String password = request.getParameter(AUTH_PASSWORD_KEY);

        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            throw new AuthenticationServiceException("Username or Password is empty");
        }

        // only assign the username and password, the authenticate flag remains false
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        // invoke authentication provider
        return this.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException
    {
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException
    {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    private static boolean validate(HttpServletRequest request) {
        boolean isSupport = true;

        // only allow POST method
        isSupport = HttpMethod.POST.name().equals(request.getMethod());

        // only allow Ajax request
        isSupport &= WebUtils.isAjax(request);

        return isSupport;
    }
}
