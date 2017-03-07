package com.mc.security.jwt.refresh;

import static com.mc.security.utils.WebUtils.JWT_SECRET_KEY;

import com.mc.config.WebSecurityConfig;
import com.mc.security.jwt.token.JwtAccessToken;
import com.mc.security.jwt.token.JwtTokenFactory;
import com.mc.security.user.DbUserDetails;
import com.mc.security.user.DbUserDetailsService;
import com.mc.security.utils.WebUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

import java.util.Date;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * Create new JWT access token by JWT refresh token.
 *
 * @author Wenyu
 * @since 3/6/17
 */
@RestController
public class JwtTokenRefreshingController {

    private final RefreshTokenVerifier refreshTokenVerifier;
    private final DbUserDetailsService dbUserDetailsService;
    private final JwtTokenFactory jwtTokenFactory;
    private final RefreshTokenBlacklistDAO refreshTokenBlacklistDAO;

    @Autowired
    public JwtTokenRefreshingController(RefreshTokenVerifier refreshTokenVerifier, DbUserDetailsService dbUserDetailsService, JwtTokenFactory jwtTokenFactory, RefreshTokenBlacklistDAO refreshTokenBlacklistDAO) {
        this.refreshTokenVerifier = refreshTokenVerifier;
        this.dbUserDetailsService = dbUserDetailsService;
        this.jwtTokenFactory = jwtTokenFactory;
        this.refreshTokenBlacklistDAO = refreshTokenBlacklistDAO;
    }

    // Any exception will be caught by the default global exception handle
    @RequestMapping(WebSecurityConfig.TOKEN_REFRESH_ENTRY_POINT)
    public @ResponseBody Map<String, String> refresh(HttpServletRequest request)
            throws AuthenticationServiceException, BadCredentialsException
    {
        String rawJwtToken = WebUtils.extractTokenFromHeader(request);
        Jws<Claims> claims = WebUtils.parseClaims(rawJwtToken, JWT_SECRET_KEY);

        String username = claims.getBody().getSubject();
        DbUserDetails userDetails = dbUserDetailsService.loadUserByUsername(username);

        // validation failure will cause exception be thrown
        refreshTokenVerifier.validate(claims);

        // add current refresh token into blacklist
        RefreshTokenBlacklist refreshTokenBlacklist = new RefreshTokenBlacklist();
        refreshTokenBlacklist.setDateCreated(new Date());
        refreshTokenBlacklist.setJti(claims.getBody().getId());
        refreshTokenBlacklist.setUser(userDetails.getUser());
        refreshTokenBlacklistDAO.save(refreshTokenBlacklist);

        JwtAccessToken accessToken = jwtTokenFactory.createAccessToken(username, userDetails.getAuthorities());

        return new JwtTokenFactory.TokenMapBuilder().with(accessToken).build();
    }
}
