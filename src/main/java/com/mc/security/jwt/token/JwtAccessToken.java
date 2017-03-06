package com.mc.security.jwt.token;

/**
 * @author Wenyu
 * @since 2/22/17
 */
public class JwtAccessToken {

    private final String value;

    public JwtAccessToken(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
