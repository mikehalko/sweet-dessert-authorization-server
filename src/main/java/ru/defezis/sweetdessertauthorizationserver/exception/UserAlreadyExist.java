package ru.defezis.sweetdessertauthorizationserver.exception;

public class UserAlreadyExist extends RuntimeException {
    public UserAlreadyExist(String username) {
        super(String.format("User %s already exist", username));
    }
}
