package com.mc.security.jwt.token;

/**
 * @author Wenyu
 * @since 3/6/17
 */
public class JwtRefreshToken {

    private final String value;

    public JwtRefreshToken(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
