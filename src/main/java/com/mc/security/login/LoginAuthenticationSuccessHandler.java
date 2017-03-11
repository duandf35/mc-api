package com.mc.security.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mc.account.models.User;
import com.mc.security.jwt.blacklist.JwtRevokedToken;
import com.mc.security.jwt.blacklist.JwtRevokedTokenDAO;
import com.mc.security.jwt.token.JwtAccessToken;
import com.mc.security.jwt.token.JwtRefreshToken;
import com.mc.security.jwt.token.JwtTokenFactory;
import com.mc.security.user.DbUserAuthority;
import com.mc.security.user.DbUserDetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * @author Wenyu
 * @since 2/19/17
 */
@Component
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper mapper = new ObjectMapper();
    private final JwtTokenFactory jwtTokenFactory;
    private final JwtRevokedTokenDAO jwtRevokedTokenDAO;

    @Autowired
    public LoginAuthenticationSuccessHandler(JwtTokenFactory jwtTokenFactory, JwtRevokedTokenDAO jwtRevokedTokenDAO) {
        this.jwtTokenFactory = jwtTokenFactory;
        this.jwtRevokedTokenDAO = jwtRevokedTokenDAO;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException
    {
        // Note: the authentication object here suppose to be the UsernamePasswordAuthenticationToken
        // which is created in the LoginAuthenticationProvider
        DbUserDetails dbUserDetails = (DbUserDetails) authentication.getPrincipal();
        Collection<DbUserAuthority> authorities = (Collection<DbUserAuthority>) authentication.getAuthorities();

        String username = dbUserDetails.getUsername();

        JwtAccessToken accessToken = jwtTokenFactory.createAccessToken(username, authorities);
        JwtRefreshToken refreshToken = jwtTokenFactory.createRefreshToken(username);

        Map<String, String> tokenMap = new JwtTokenFactory.TokenMapBuilder()
                .with(accessToken)
                .with(refreshToken)
                .build();

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // json string
        mapper.writeValue(response.getWriter(), tokenMap);

        clearAuthenticationAttributes(request);
        clearRevokedTokens(dbUserDetails.getUser());
    }

    /**
     * TODO: is this necessary?
     * Clear other authentication related attributes.
     *
     * @param request
     */
    private void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }
    }

    private void clearRevokedTokens(User user) {
        Set<JwtRevokedToken> jwtRevokedTokens = jwtRevokedTokenDAO.findByUser(user);

        if (jwtRevokedTokens != null && !jwtRevokedTokens.isEmpty()) {
            jwtRevokedTokenDAO.delete(jwtRevokedTokens);
        }
    }
}
