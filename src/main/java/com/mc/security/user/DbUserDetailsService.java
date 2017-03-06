package com.mc.security.user;

import com.mc.account.daos.UserDAO;
import com.mc.account.models.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Database-backed user details service which is required by the
 * Spring's authentication related components.
 *
 * @author Wenyu
 * @since 2/19/17
 */
@Service
public class DbUserDetailsService implements UserDetailsService {

    private final UserDAO userDAO;

    @Autowired
    public DbUserDetailsService(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userDAO.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return new DbUserDetails(user);
    }
}
