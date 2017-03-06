package com.mc.security.jwt;

/**
 * @author Wenyu
 * @since 3/4/17
 */
public class JwtSettings {

    public static final String CLAIMS_SCOPE = "scopes";

    public static final String ISSUER = "mc";

    public static final int ACCESS_EXPIRATION_MIN = 30;

    public static final int REFRESH_EXPIRATION_MIN = 60;

    public static final String SECRET_KEY = "7a514562f44347859490475d2e71cb1c";
}
