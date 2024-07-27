package ru.defezis.sweetdessertauthorizationserver.exception;

public class UserNotFound extends RuntimeException {
    public UserNotFound(String username) {
        super(String.format("User %s does not exist", username));
    }
}
