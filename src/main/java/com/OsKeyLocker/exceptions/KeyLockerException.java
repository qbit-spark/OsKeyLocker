package com.OsKeyLocker.exceptions;

/**
 * Exception thrown when secure storage operations fail
 */
public class KeyLockerException extends Exception {

    public KeyLockerException(String message) {
        super(message);
    }

    public KeyLockerException(String message, Throwable cause) {
        super(message, cause);
    }
}