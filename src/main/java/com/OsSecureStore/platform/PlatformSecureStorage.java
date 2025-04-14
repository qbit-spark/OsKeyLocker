package com.OsSecureStore.platform;

import com.OsSecureStore.exceptions.SecureStorageException;

/**
 * Platform-specific secure storage interface
 * Provides operations for secure credential storage
 */
public interface PlatformSecureStorage {

    /**
     * Encrypts data using platform-specific secure storage
     * @param data The data to encrypt
     * @return The encrypted data
     * @throws SecureStorageException if encryption fails
     */
    byte[] encrypt(byte[] data) throws SecureStorageException;

    /**
     * Decrypts data using platform-specific secure storage
     * @param encryptedData The encrypted data to decrypt
     * @return The decrypted data
     * @throws SecureStorageException if decryption fails
     */
    byte[] decrypt(byte[] encryptedData) throws SecureStorageException;

    /**
     * Initializes the secure storage
     * @throws SecureStorageException if initialization fails
     */
    void initialize() throws SecureStorageException;

    /**
     * Checks if this platform implementation is supported on the current system
     * @return true if supported, false otherwise
     */
    boolean isSupported();

    /**
     * Sets the application prefix for credentials
     * @param prefix Application prefix
     * @throws SecureStorageException if the operation fails
     */
    void setAppPrefix(String prefix) throws SecureStorageException;
}