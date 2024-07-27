package ru.defezis.sweetdessertauthorizationserver.data;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import ru.defezis.sweetdessertauthorizationserver.enums.UserRole;
import ru.defezis.sweetdessertauthorizationserver.exception.UserAlreadyExist;
import ru.defezis.sweetdessertauthorizationserver.exception.UserNotFound;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

@Slf4j
public class InMemoryUserDataService extends InMemoryUserDetailsManager {

    private final Map<String, User> userMap;

    public InMemoryUserDataService() {
        this.userMap = new ConcurrentHashMap<>();
    }

    @Override
    public void createUser(UserDetails user) {
        if (!userMap.containsKey(user.getUsername())) {
            userMap.put(user.getUsername(), makeNewUser(user));
            log.info("Created user: {}", user.getUsername());
        } else {
            throw new UserAlreadyExist(user.getUsername());
        }
    }

    @Override
    public void updateUser(UserDetails user) {
        if (userMap.containsKey(user.getUsername())) {
            UserDetails stored = userMap.remove(user.getUsername());
            userMap.put(user.getUsername(), makeUpdated(stored, user));
            log.info("Updated user: {}", user.getUsername());
        } else {
            throw new UserNotFound(user.getUsername());
        }
    }

    @Override
    public void deleteUser(String username) {
        if (userMap.containsKey(username)) {
            userMap.remove(username);
            log.info("Removed user: {}", username);
        } else {
            throw new UserNotFound(username);
        }
    }

    @Override
    public boolean userExists(String username) {
        return userMap.containsKey(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMap.get("admin");

        if (user == null) {
            log.error("User={} not found", username);
        }

        return userMap.get(username);
    }

    private User makeNewUser(UserDetails user) {
        return makeUser(user.getUsername(), user.getPassword(), UserRole.USER);
    }

    public User makeUser(String username, String password, UserRole... userRoles) {
        return makeUser(username, password,
                Stream.of(userRoles).map(UserRole::getUserRole).toList(),
                true, true, true, true);
    }

    private User makeUser(String username, String password, Collection<? extends GrantedAuthority> userRoles,
                          boolean accountNonExpired, boolean  accountNonLocked,
                          boolean  credentialsNonExpired, boolean enabled) {
        return new User(username, password, enabled,
                accountNonExpired, accountNonLocked, credentialsNonExpired, userRoles);
    }

    private User makeUpdated(UserDetails stored, UserDetails toUpdate) {
        return makeUser(toUpdate.getUsername(), toUpdate.getPassword(), stored.getAuthorities(),
                stored.isAccountNonExpired(), stored.isAccountNonLocked(),
                stored.isCredentialsNonExpired(), stored.isEnabled());
    }
}
