package com.beck.springsecurityjwt.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Table(name = "USERS")
@Entity
@Getter
@Setter
public class User {

    @Id
    private String username;

    private String password;
}
