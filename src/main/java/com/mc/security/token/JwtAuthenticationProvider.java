package com.mc.security.token;

import com.mc.models.UserRole;
import com.mc.security.user.DbUserAuthority;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * @author Wenyu
 * @since 2/18/17
 */
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // this provider is expecting an UsernamePasswordAuthenticationToken object
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;

        String rawJwtToken = (String) authenticationToken.getCredentials();
        Jws<Claims> jwsClaims = parseClaims(rawJwtToken, JwtSettings.SECRET_KEY);

        String subject = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get(JwtSettings.CLAIMS_SCOPE, List.class);
        List<DbUserAuthority> authorities = scopes.stream()
                .map(authority -> new DbUserAuthority(UserRole.valueOf(authority)))
                .collect(Collectors.toList());

        return new JwtAuthenticationToken(subject, authorities);
    }

    /**
     * This support method will determine if this provider should be applied.
     *
     * @param authentication
     * @return true if the passing Authentication object matches the expected type
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static Jws<Claims> parseClaims(String rawJwtToken, String jwtSecret) {
        try {
            return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(rawJwtToken);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid JWT token", e);
        } catch (ExpiredJwtException e) {
            throw e; // just indicate that token may be expired
        }
    }

}
