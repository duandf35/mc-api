package com.mc.security.utils;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * @author Wenyu
 * @since 3/5/17
 */
public final class WebUtils {

    // ================================= Login =================================

    public static final String AUTH_USERNAME_KEY = "username";

    public static final String AUTH_PASSWORD_KEY = "password";

    // http://stackoverflow.com/questions/17478731/whats-the-point-of-the-x-requested-with-header
    // | Without CORS it is not possible to add X-Requested-With to a cross domain XHR request.
    private static final String AJAX_HEADER_KEY = "X-Requested-With";

    private static final String AJAX_HEADER_VALUE = "XMLHttpRequest";

    public static boolean isAjax(HttpServletRequest request) {
        return request.getHeader(AJAX_HEADER_KEY).contains(AJAX_HEADER_VALUE);
    }

    // ================================= JWT =================================

    public static final int JWT_ACCESS_EXPIRATION_MIN = 30;

    public static final int JWT_REFRESH_EXPIRATION_MIN = 60;

    public static final String JWT_ACCESS_TOKEN = "access";

    public static final String JWT_REFRESH_TOKEN = "refresh";

    public static final String JWT_CLAIMS_SCOPE = "scopes";

    public static final String JWT_ISSUER = "mc";

    public static final String JWT_SECRET_KEY = "7a514562f44347859490475d2e71cb1c";

    private static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";

    private static final String JWT_TOKEN_HEADER_PREFIX = "Bearer ";

    /**
     * Extract JWT token from request header.
     *
     * Never send authentication token via cookies. The attacker can send request from any domain,
     * although the attacker can not access your cookies due to the domain is different, the browser
     * will still INCLUDE all your cookies in the request!
     *
     * The token should always be sent via the header since only the JS on your domain can access the
     * cookie (read token from the cookie and put it into the request header)!
     *
     * @param request
     * @return
     */
    public static String extractTokenFromHeader(HttpServletRequest request) {
        String jwtTokenHeader = request.getHeader(JWT_TOKEN_HEADER_PARAM);

        if (StringUtils.isEmpty(jwtTokenHeader) || jwtTokenHeader.length() < JWT_TOKEN_HEADER_PREFIX.length()) {
            throw new AuthenticationServiceException("Authorization header is invalid");
        }

        return jwtTokenHeader.substring(JWT_TOKEN_HEADER_PREFIX.length(), jwtTokenHeader.length());
    }

    public static Jws<Claims> parseClaims(String rawJwtToken, String jwtSecret) {
        try {
            return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(rawJwtToken);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid JWT token", e);
        } catch (ExpiredJwtException e) {
            throw new BadCredentialsException("Expired JWT token", e);
        }
    }

    private WebUtils() {

    }
}
