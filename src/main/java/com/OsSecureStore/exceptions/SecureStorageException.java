package com.OsSecureStore.exceptions;

/**
 * Exception thrown when secure storage operations fail
 */
public class SecureStorageException extends Exception {

    public SecureStorageException(String message) {
        super(message);
    }

    public SecureStorageException(String message, Throwable cause) {
        super(message, cause);
    }
}