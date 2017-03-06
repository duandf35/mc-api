package com.mc.security.token;

import static com.mc.security.token.JwtSettings.ACCESS_EXPIRATION_MIN;
import static com.mc.security.token.JwtSettings.CLAIMS_SCOPE;
import static com.mc.security.token.JwtSettings.ISSUER;
import static com.mc.security.token.JwtSettings.REFRESH_EXPIRATION_MIN;
import static com.mc.security.token.JwtSettings.SECRET_KEY;

import com.mc.models.UserRole;
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

    public JwtToken createAccessToken(String username, Collection<DbUserAuthority> authorities) {
        if (StringUtils.isEmpty(username)) {
            throw new IllegalArgumentException("Username is missing when creating access token");
        }

        if (authorities == null || authorities.isEmpty()) {
            throw new IllegalArgumentException("Authorities is missing when creating access token");
        }

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(CLAIMS_SCOPE, authorities.stream()
                .map(DbUserAuthority::getAuthority)
                .collect(Collectors.toList()));

        DateTime current = new DateTime();
        DateTime expiration = current.plusMinutes(ACCESS_EXPIRATION_MIN);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(ISSUER)
                .setIssuedAt(current.toDate())
                .setExpiration(expiration.toDate())
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();

        return new JwtToken(token, claims);
    }

    public JwtToken createRefreshToken(String username) {
        if (StringUtils.isEmpty(username)) {
            throw new IllegalArgumentException("Username is missing when creating access token");
        }

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(CLAIMS_SCOPE, Collections.singletonList(UserRole.REFRESH));

        DateTime current = new DateTime();
        DateTime expiration = current.plusMinutes(REFRESH_EXPIRATION_MIN);

        String token = Jwts.builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setIssuer(ISSUER)
                .setIssuedAt(current.toDate())
                .setExpiration(expiration.toDate())
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();

        return new JwtToken(token, claims);
    }
}
