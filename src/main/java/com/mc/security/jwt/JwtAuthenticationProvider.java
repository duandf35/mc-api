package com.mc.security.jwt;

import static com.mc.security.utils.WebUtils.JWT_CLAIMS_SCOPE;
import static com.mc.security.utils.WebUtils.JWT_SECRET_KEY;

import com.mc.account.models.UserRole;
import com.mc.security.user.DbUserAuthority;
import com.mc.security.utils.WebUtils;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

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
        Jws<Claims> jwsClaims = WebUtils.parseClaims(rawJwtToken, JWT_SECRET_KEY);

        String subject = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get(JWT_CLAIMS_SCOPE, List.class);
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
}
