package com.mc.security.login;

import com.fasterxml.jackson.databind.ObjectMapper;

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

        LoginCommand loginCommand = objectMapper.readValue(request.getReader(), LoginCommand.class);

        if (StringUtils.isEmpty(loginCommand.getUsername()) || StringUtils.isEmpty(loginCommand.getPassword())) {
            throw new AuthenticationServiceException("Username or Password is empty");
        }

        // only assign the username and password, the authenticate flag remains false
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginCommand.getUsername(), loginCommand.getPassword());

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
        isSupport &= isAjax(request);

        return isSupport;
    }

    // http://stackoverflow.com/questions/17478731/whats-the-point-of-the-x-requested-with-header
    // | Without CORS it is not possible to add X-Requested-With to a cross domain XHR request.
    private static final String AJAX_HEADER_KEY = "X-Requested-With";

    private static final String AJAX_HEADER_VALUE = "XMLHttpRequest";

    private static boolean isAjax(HttpServletRequest request) {
        return request.getHeader(AJAX_HEADER_KEY).contains(AJAX_HEADER_VALUE);
    }
}
