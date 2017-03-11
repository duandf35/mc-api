package com.mc.security.jwt.controllers;

import static com.mc.security.utils.WebUtils.JWT_SECRET_KEY;

import com.mc.config.WebSecurityConfig;
import com.mc.security.jwt.blacklist.JwtRevokedToken;
import com.mc.security.jwt.blacklist.JwtRevokedTokenDAO;
import com.mc.security.user.DbUserDetails;
import com.mc.security.user.DbUserDetailsService;
import com.mc.security.utils.WebUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * @author Wenyu
 * @since 3/10/17
 */
@RestController
public class JwtTokenRevokingController {

    private final DbUserDetailsService dbUserDetailsService;
    private final JwtRevokedTokenDAO jwtRevokedTokenDAO;

    @Autowired
    public JwtTokenRevokingController(DbUserDetailsService dbUserDetailsService, JwtRevokedTokenDAO jwtRevokedTokenDAO) {
        this.dbUserDetailsService = dbUserDetailsService;
        this.jwtRevokedTokenDAO = jwtRevokedTokenDAO;
    }

    @RequestMapping(WebSecurityConfig.TOKEN_REVOKE_ENTRY_POINT)
    public @ResponseBody String revoke(HttpServletRequest request) {
        String rawJwtToken = WebUtils.extractTokenFromHeader(request);
        Jws<Claims> claims = WebUtils.parseClaims(rawJwtToken, JWT_SECRET_KEY);

        String username = claims.getBody().getSubject();
        DbUserDetails userDetails = dbUserDetailsService.loadUserByUsername(username);

        JwtRevokedToken jwtRevokedToken = new JwtRevokedToken();
        jwtRevokedToken.setDateCreated(new Date());
        jwtRevokedToken.setJti(claims.getBody().getId());
        jwtRevokedToken.setUser(userDetails.getUser());
        jwtRevokedTokenDAO.save(jwtRevokedToken);

        return "Token has been revoked";
    }
}
