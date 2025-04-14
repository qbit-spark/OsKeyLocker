package com.OsSecureStore.platform.windows;

import com.OsSecureStore.exceptions.SecureStorageException;
import com.OsSecureStore.platform.PlatformSecureStorage;
import com.OsSecureStore.util.PlatformDetector;

/**
 * Windows implementation of secure storage using Windows Credential Manager
 */
public class WindowsSecureStorage implements PlatformSecureStorage {

    private WindowsCredentialManager credManager;
    private boolean initialized = false;

    /**
     * Creates a new WindowsSecureStorage instance
     */
    public WindowsSecureStorage() {
        this.credManager = new WindowsCredentialManager();
    }

    @Override
    public byte[] encrypt(byte[] data) throws SecureStorageException {
        // This method is kept for API compatibility but will not be used
        throw new SecureStorageException("Direct encryption not supported; use storeCredential instead");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws SecureStorageException {
        // This method is kept for API compatibility but will not be used
        throw new SecureStorageException("Direct decryption not supported; use retrieveCredential instead");
    }

    /**
     * Sets the application prefix for credential names
     * @param prefix Application name prefix
     */
    @Override
    public void setAppPrefix(String prefix) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        System.out.println("Setting application prefix: " + prefix);
        credManager.setAppPrefix(prefix);
    }

    /**
     * Stores a credential in Windows Credential Manager
     * @param key The credential key/target name
     * @param value The credential value/password
     * @throws SecureStorageException if storage fails
     */
    public void storeCredential(String key, String value) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        try {
            //System.out.println("Storing credential with key: " + key);
            credManager.addCredential(key, value);
        } catch (Exception e) {
            throw new SecureStorageException("Failed to store credential", e);
        }
    }

    /**
     * Retrieves a credential from Windows Credential Manager
     * @param key The credential key/target name
     * @return The credential value/password, or null if not found
     * @throws SecureStorageException if retrieval fails
     */
    public String retrieveCredential(String key) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        try {
            return credManager.getCredential(key);
        } catch (Exception e) {
            if (e.getMessage().contains("not found")) {
                return null;
            }
            throw new SecureStorageException("Failed to retrieve credential", e);
        }
    }

    /**
     * Removes a credential from Windows Credential Manager
     * @param key The credential key/target name
     * @throws SecureStorageException if removal fails
     */
    public void removeCredential(String key) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        try {
            credManager.deleteCredential(key);
        } catch (Exception e) {
            throw new SecureStorageException("Failed to remove credential", e);
        }
    }

    /**
     * Checks if a credential exists in Windows Credential Manager
     * @param key The credential key/target name
     * @return true if the credential exists, false otherwise
     * @throws SecureStorageException if the check fails
     */
    public boolean credentialExists(String key) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        try {
            return credManager.credentialExists(key);
        } catch (Exception e) {
            throw new SecureStorageException("Failed to check if credential exists", e);
        }
    }

    @Override
    public void initialize() throws SecureStorageException {
        if (!isSupported()) {
            throw new SecureStorageException("Windows platform is not supported on this system");
        }

        try {
            credManager.initialize();
            initialized = true;
        } catch (Exception e) {
            throw new SecureStorageException("Failed to initialize Windows credential manager", e);
        }
    }

    @Override
    public boolean isSupported() {
        return PlatformDetector.isWindows();
    }
}