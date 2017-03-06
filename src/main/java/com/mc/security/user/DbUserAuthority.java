package com.mc.security.user;

import com.mc.account.models.UserRole;

import org.springframework.security.core.GrantedAuthority;

/**
 * @author Wenyu
 * @since 2/19/17
 */
public class DbUserAuthority implements GrantedAuthority {

    private final UserRole userRole;

    public DbUserAuthority(UserRole userRole) {
        this.userRole = userRole;
    }

    @Override
    public String getAuthority() {
        return userRole.name();
    }
}
