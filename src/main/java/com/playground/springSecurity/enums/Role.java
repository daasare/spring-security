package com.playground.springSecurity.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;

@Getter
public enum Role {

    ADMIN(Set.of(Permission.WRITE, Permission.READ, Permission.DELETE)),
    USER(Set.of(Permission.READ));


    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    // convert roles into "GrantedAuthority" which is what spring security understands
    public List<GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_"+this.name()));
    }

}
