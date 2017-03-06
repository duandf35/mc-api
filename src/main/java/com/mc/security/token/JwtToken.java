package com.mc.security.token;

import io.jsonwebtoken.Claims;

/**
 * @author Wenyu
 * @since 2/22/17
 */
public class JwtToken {

    private final String token;

    private final Claims claims;

    public JwtToken(String token, Claims claims) {
        this.token = token;
        this.claims = claims;
    }

    public String getToken() {
        return token;
    }

    public Claims getClaims() {
        return claims;
    }
}
