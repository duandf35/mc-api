package com.mc.security.jwt.verify;

import com.mc.account.models.User;

import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import javax.validation.constraints.NotNull;

import java.util.Date;

/**
 * @author Wenyu
 * @since 3/6/17
 */
@Entity(name = "refresh_token_blacklist")
public class RefreshTokenBlacklist {

    @Id
    @GeneratedValue
    private Integer id;

    @NotNull
    private String jti;

    @DateTimeFormat
    @NotNull
    private Date dateCreated;

    @OneToOne(cascade = CascadeType.REMOVE)
    @NotNull
    private User user;

    public RefreshTokenBlacklist() {

    }

    public Integer getId() {
        return this.id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getJti() {
        return this.jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public Date getDateCreated() {
        return this.dateCreated;
    }

    public void setDateCreated(Date dateCreated) {
        this.dateCreated = dateCreated;
    }

    public User getUser() {
        return this.user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
