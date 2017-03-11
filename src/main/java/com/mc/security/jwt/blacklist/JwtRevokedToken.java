package com.mc.security.jwt.blacklist;

import com.mc.account.models.User;

import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.validation.constraints.NotNull;

import java.util.Date;

/**
 * @author Wenyu
 * @since 3/6/17
 */
@Entity(name = "jwt_revoked_token")
public class JwtRevokedToken {

    @Id
    @GeneratedValue
    private Integer id;

    @NotNull
    private String jti;

    @DateTimeFormat
    @NotNull
    private Date dateCreated;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    @NotNull
    private User user;

    public JwtRevokedToken() {

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
