package ru.defezis.sweetdessertauthorizationserver.enums;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Getter
public enum UserRole {
    ADMIN("ADMIN"), USER("USER");

    private final String name;
    private final String nameWithPrefix;

    UserRole(String name) {
        this.name = name;
        this.nameWithPrefix = "ROLE_" + name;
    }

    public GrantedAuthority getUserRole() {
        return new SimpleGrantedAuthority(nameWithPrefix);
    }

    @Override
    public String toString() {
        return this.getNameWithPrefix();
    }
}
