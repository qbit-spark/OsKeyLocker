package com.OsKeyLocker.platform;

import com.OsKeyLocker.exceptions.KeyLockerException;

/**
 * Platform-specific secure storage interface
 * Provides operations for secure credential storage
 */
public interface PlatformKeyLockerStorage {

    /**
     * Encrypts data using platform-specific secure storage
     * @param data The data to encrypt
     * @return The encrypted data
     * @throws KeyLockerException if encryption fails
     */
    byte[] encrypt(byte[] data) throws KeyLockerException;

    /**
     * Decrypts data using platform-specific secure storage
     * @param encryptedData The encrypted data to decrypt
     * @return The decrypted data
     * @throws KeyLockerException if decryption fails
     */
    byte[] decrypt(byte[] encryptedData) throws KeyLockerException;

    /**
     * Initializes the secure storage
     * @throws KeyLockerException if initialization fails
     */
    void initialize() throws KeyLockerException;

    /**
     * Checks if this platform implementation is supported on the current system
     * @return true if supported, false otherwise
     */
    boolean isSupported();

    /**
     * Sets the application prefix for credentials
     * @param prefix Application prefix
     * @throws KeyLockerException if the operation fails
     */
    void setAppPrefix(String prefix) throws KeyLockerException;
}