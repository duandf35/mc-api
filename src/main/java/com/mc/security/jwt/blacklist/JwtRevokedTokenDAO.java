package com.mc.security.jwt.blacklist;

import com.mc.account.models.User;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

import java.util.Set;

/**
 * @author Wenyu
 * @since 3/6/17
 */
@Component
@Transactional
public interface JwtRevokedTokenDAO extends CrudRepository<JwtRevokedToken, Long> {

    JwtRevokedToken findByJti(String jti);

    Set<JwtRevokedToken> findByUser(User user);
}
