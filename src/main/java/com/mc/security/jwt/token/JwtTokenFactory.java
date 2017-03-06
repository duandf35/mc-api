package com.mc.security.jwt.token;

import static com.mc.security.jwt.JwtSettings.ACCESS_EXPIRATION_MIN;
import static com.mc.security.jwt.JwtSettings.CLAIMS_SCOPE;
import static com.mc.security.jwt.JwtSettings.ISSUER;
import static com.mc.security.jwt.JwtSettings.REFRESH_EXPIRATION_MIN;
import static com.mc.security.jwt.JwtSettings.SECRET_KEY;

import com.mc.account.models.UserRole;
import com.mc.security.user.DbUserAuthority;

import org.joda.time.DateTime;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @author Wenyu
 * @since 2/19/17
 */
@Component
public class JwtTokenFactory {

    public JwtAccessToken createAccessToken(String username, Collection<DbUserAuthority> authorities) {
        if (StringUtils.isEmpty(username)) {
            throw new IllegalArgumentException("Username is missing when creating access jwt");
        }

        if (authorities == null || authorities.isEmpty()) {
            throw new IllegalArgumentException("Authorities is missing when creating access jwt");
        }

        Claims claims = Jwts.claims()
                .setSubject(username);
        claims.put(CLAIMS_SCOPE, authorities.stream()
                .map(DbUserAuthority::getAuthority)
                .collect(Collectors.toList()));

        DateTime current = new DateTime();
        DateTime expiration = current.plusMinutes(ACCESS_EXPIRATION_MIN);

        // Jwts.builder().setClaims() will create a default subject which means if setClaims() is called after
        // Jwts.builder().setSubject(), the previous subject will be lost
        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(ISSUER)
                .setIssuedAt(current.toDate())
                .setExpiration(expiration.toDate())
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();

        return new JwtAccessToken(token);
    }

    /**
     * Refresh jwt which has a longer expiration for re-building access jwt.
     *
     * The refresh jwt doesn't contain the user authorities.
     *
     * @param username
     * @return
     */
    public JwtRefreshToken createRefreshToken(String username) {
        if (StringUtils.isEmpty(username)) {
            throw new IllegalArgumentException("Username is missing when creating access jwt");
        }

        Claims claims = Jwts.claims()
                .setSubject(username)
                .setId(UUID.randomUUID().toString()); // JTI
        claims.put(CLAIMS_SCOPE, Collections.singletonList(UserRole.REFRESH));

        DateTime current = new DateTime();
        DateTime expiration = current.plusMinutes(REFRESH_EXPIRATION_MIN);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(ISSUER)
                .setIssuedAt(current.toDate())
                .setExpiration(expiration.toDate())
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();

        return new JwtRefreshToken(token);
    }
}
