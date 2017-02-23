package com.mc.config;

import com.mc.security.JwtAuthenticationFilter;
import com.mc.security.JwtLoginFilter;
import com.mc.security.user.DbUserDetailsService;
import com.mc.security.utils.JwtAuthenticationProvider;
import com.mc.security.utils.UserDetailProvider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author Wenyu
 * @since 2/11/17
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final DbUserDetailsService dbUserDetailsService;

    @Autowired
    public WebSecurityConfig(JwtAuthenticationProvider jwtAuthenticationProvider, DbUserDetailsService dbUserDetailsService) {
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
        this.dbUserDetailsService = dbUserDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().cacheControl(); // disable caching

        http
                .csrf().disable() // jwt doesn't need csrf protection
                .authorizeRequests()
                    .antMatchers("/", "/login").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
// default login page will be used if it is not specified
//                    .loginPage("/login")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll()
                    .and()
                .addFilterBefore(new JwtLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthenticationFilter(jwtAuthenticationProvider),
                        UsernamePasswordAuthenticationFilter.class);
    }

    // --------- register custom UserDetailsService ---------

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(dbUserDetailsService).passwordEncoder(new BCryptPasswordEncoder());
//    }
//
//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        return dbUserDetailsService;
//    }

    // --------- register custom UserDetailsService ---------
}
