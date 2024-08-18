package ru.defezis.sweetdessertauthorizationserver.data;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.defezis.sweetdessertauthorizationserver.model.User;

import java.util.Collections;

@Slf4j
public class InMemoryUserRepository implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    public InMemoryUserRepository(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        log.info("loadUserByUsername");
        return new User(s, passwordEncoder.encode("0"), Collections.emptyList(), true, true, true, true);
    }
}
