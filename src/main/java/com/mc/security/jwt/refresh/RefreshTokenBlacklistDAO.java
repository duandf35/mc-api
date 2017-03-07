package com.mc.security.jwt.refresh;

import com.mc.account.models.User;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

/**
 * @author Wenyu
 * @since 3/6/17
 */
@Component
@Transactional
public interface RefreshTokenBlacklistDAO extends CrudRepository<RefreshTokenBlacklist, Long> {

    RefreshTokenBlacklist findByJti(String jti);

    RefreshTokenBlacklist findByUser(User user);
}
