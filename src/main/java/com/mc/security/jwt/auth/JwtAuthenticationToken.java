package com.mc.security.jwt.auth;

import com.mc.security.user.DbUserAuthority;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collection;

/**
 * DTO to transfer raw JWT token to authentication provider.
 *
 * @author Wenyu
 * @since 3/4/17
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private Object credentials;

    /**
     * Before authentication, set the raw JWT token.
     *
     * @param rawJwtToken
     */
    public JwtAuthenticationToken(String rawJwtToken) {
        super(null);
        this.credentials = rawJwtToken;
        setAuthenticated(false);
    }

    /**
     * After authentication, set the credentials and authorities.
     *
     * @param credentials
     * @param authorities
     */
    public JwtAuthenticationToken(String credentials, Collection<DbUserAuthority> authorities) {
        super(authorities);
        this.credentials = credentials;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    // not use
    @Override
    public Object getPrincipal() {
        return null;
    }


    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }
}
