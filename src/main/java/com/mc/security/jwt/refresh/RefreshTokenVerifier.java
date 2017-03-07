package com.mc.security.jwt.refresh;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * @author Wenyu
 * @since 3/6/17
 */
@Component
public class RefreshTokenVerifier {

    private final RefreshTokenBlacklistDAO refreshTokenBlacklistDAO;

    @Autowired
    public RefreshTokenVerifier(RefreshTokenBlacklistDAO refreshTokenBlacklistDAO) {
        this.refreshTokenBlacklistDAO = refreshTokenBlacklistDAO;
    }

    /**
     * Throw BadCredentialsException is the refresh token is in the blacklist.
     *
     * @param claims
     */
    public void validate(Jws<Claims> claims) {

        String jti = claims.getBody().getId();

        if (StringUtils.isEmpty(jti) || refreshTokenBlacklistDAO.findByJti(jti) != null) {
            throw new BadCredentialsException("Refresh token is invalid");
        }
    }
}
