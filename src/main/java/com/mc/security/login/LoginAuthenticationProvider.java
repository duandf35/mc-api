package com.mc.security.login;

import com.mc.security.user.DbUserDetails;
import com.mc.security.user.DbUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author Wenyu
 * @since 2/18/17
 */
@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final DbUserDetailsService dbUserDetailsService;

    @Autowired
    public LoginAuthenticationProvider(BCryptPasswordEncoder bCryptPasswordEncoder, DbUserDetailsService dbUserDetailsService) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.dbUserDetailsService = dbUserDetailsService;
    }

    /**
     * Authenticate users with username and password by the custom UserDetailsService.
     *
     * @param authentication the object hold provided username and password
     * @return authentication token if authenticate success
     * @throws AuthenticationException authentication exception if authenticate fail
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // this provider is expecting an UsernamePasswordAuthenticationToken object
        UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) authentication;

        String username = (String) authenticationToken.getPrincipal();
        String password = (String) authenticationToken.getCredentials();

        DbUserDetails user = dbUserDetailsService.loadUserByUsername(username);

        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Password not valid");
        }

        if (user.getAuthorities() == null) {
            throw new InsufficientAuthenticationException("User: " + username + " has no role assigned");
        }

        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
    }

    /**
     * This support method will determine if this provider should be applied.
     *
     * @param authentication
     * @return true if the passing Authentication object matches the expected type
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
