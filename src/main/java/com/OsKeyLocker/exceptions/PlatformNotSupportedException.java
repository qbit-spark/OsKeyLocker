package com.OsKeyLocker.exceptions;

/**
 * Exception thrown when the current platform is not supported
 */
public class PlatformNotSupportedException extends KeyLockerException {

    public PlatformNotSupportedException(String message) {
        super(message);
    }

    public PlatformNotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}