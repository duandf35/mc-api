package com.mc.security.jwt.blacklist;

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
public class JwtTokenVerifier {

    private final JwtRevokedTokenDAO jwtRevokedTokenDAO;

    @Autowired
    public JwtTokenVerifier(JwtRevokedTokenDAO jwtRevokedTokenDAO) {
        this.jwtRevokedTokenDAO = jwtRevokedTokenDAO;
    }

    /**
     * Throw BadCredentialsException is the blacklist token is in the blacklist.
     *
     * @param claims
     */
    public void validate(Jws<Claims> claims) {

        String jti = claims.getBody().getId();

        if (StringUtils.isEmpty(jti) || jwtRevokedTokenDAO.findByJti(jti) != null) {
            throw new BadCredentialsException("Token has been revoked");
        }
    }
}
