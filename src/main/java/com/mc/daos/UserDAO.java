package com.mc.daos;

import com.mc.models.User;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

/**
 * @author Wenyu
 * @since 2/11/17
 */
@Component
@Transactional
public interface UserDAO extends CrudRepository<User, Long> {

    User findByUsername(String username);
}
