package com.OsKeyLocker.platform.windows;


import com.OsKeyLocker.exceptions.KeyLockerException;
import com.OsKeyLocker.platform.PlatformKeyLockerStorage;
import com.OsKeyLocker.util.EncryptionUtil;
import com.OsKeyLocker.util.PlatformDetector;
import org.json.JSONObject;

/**
 * Windows implementation of secure storage using Windows Credential Manager
 */
public class WindowsSecureStorage implements PlatformKeyLockerStorage {

    private WindowsCredentialManager credManager;
    private EncryptionUtil encryptionUtil;
    private boolean initialized = false;

    /**
     * Creates a new WindowsSecureStorage instance
     */
    public WindowsSecureStorage() {
        this.credManager = new WindowsCredentialManager();
    }

    /**
     * Initialize with app package name and encryption key
     * @param packageName The application package name
     * @param encryptionKey The encryption key to use
     * @throws KeyLockerException if initialization fails
     */
    public void initialize(String packageName, String encryptionKey) throws KeyLockerException {
        if (!isSupported()) {
            throw new KeyLockerException("Windows platform is not supported on this system");
        }

        try {
            credManager.setAppPrefix(packageName);
            credManager.initialize(encryptionKey);
            this.encryptionUtil = new EncryptionUtil(encryptionKey);
            initialized = true;
        } catch (Exception e) {
            throw new KeyLockerException("Failed to initialize Windows credential manager", e);
        }
    }

    /**
     * Sets the encryption key for the credential manager
     * @param encryptionKey The encryption key to use
     * @throws KeyLockerException if the operation fails
     */
    public void setEncryptionKey(String encryptionKey) throws KeyLockerException {
        if (!initialized) {
            throw new KeyLockerException("WindowsKeyLocker not initialized");
        }

        try {
            this.encryptionUtil = new EncryptionUtil(encryptionKey);
            credManager.setEncryptionKey(encryptionKey);
        } catch (Exception e) {
            throw new KeyLockerException("Failed to set encryption key", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data) throws KeyLockerException {
        // This method is kept for API compatibility but will not be used directly
        throw new KeyLockerException("Direct encryption not supported; use storeJsonCredential instead");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws KeyLockerException {
        // This method is kept for API compatibility but will not be used directly
        throw new KeyLockerException("Direct decryption not supported; use retrieveJsonCredential instead");
    }

    /**
     * Sets the application prefix for credential names
     * @param prefix Application name prefix
     */
    @Override
    public void setAppPrefix(String prefix) throws KeyLockerException {
        if (!initialized) {
            initialize();
        }
        credManager.setAppPrefix(prefix);
    }

    /**
     * Stores a JSON credential in Windows Credential Manager
     * @param key The credential key/target name
     * @param jsonData The JSON data to store
     * @throws KeyLockerException if storage fails
     */
    public void storeJsonCredential(String key, JSONObject jsonData) throws KeyLockerException {
        if (!initialized) {
            throw new KeyLockerException("WindowsKeyLocker not initialized");
        }

        try {
            credManager.addCredential(key, jsonData);
        } catch (Exception e) {
            throw new KeyLockerException("Failed to store credential", e);
        }
    }

    /**
     * Retrieves a JSON credential from Windows Credential Manager
     * @param key The credential key/target name
     * @return The JSON data, or null if not found
     * @throws KeyLockerException if retrieval fails
     */
    public JSONObject retrieveJsonCredential(String key) throws KeyLockerException {
        if (!initialized) {
            throw new KeyLockerException("WindowsKeyLocker not initialized");
        }

        try {
            return credManager.getCredential(key);
        } catch (Exception e) {
            if (e.getMessage().contains("not found")) {
                return null;
            }
            throw new KeyLockerException("Failed to retrieve credential", e);
        }
    }

    /**
     * Updates a specific field in a JSON credential
     * @param key The credential key/target name
     * @param jsonKey The JSON field to update
     * @param jsonValue The new value for the field
     * @throws KeyLockerException if the operation fails
     */
    public void updateCredentialField(String key, String jsonKey, Object jsonValue) throws KeyLockerException {
        if (!initialized) {
            throw new KeyLockerException("WindowsKeyLocker not initialized");
        }

        try {
            credManager.updateCredentialField(key, jsonKey, jsonValue);
        } catch (Exception e) {
            throw new KeyLockerException("Failed to update credential field", e);
        }
    }

    /**
     * Removes a credential from Windows Credential Manager
     * @param key The credential key/target name
     * @throws KeyLockerException if removal fails
     */
    public void removeCredential(String key) throws KeyLockerException {
        if (!initialized) {
            throw new KeyLockerException("WindowsKeyLocker not initialized");
        }

        try {
            credManager.deleteCredential(key);
        } catch (Exception e) {
            throw new KeyLockerException("Failed to remove credential", e);
        }
    }

    /**
     * Checks if a credential exists in Windows Credential Manager
     * @param key The credential key/target name
     * @return true if the credential exists, false otherwise
     * @throws KeyLockerException if the check fails
     */
    public boolean credentialExists(String key) throws KeyLockerException {
        if (!initialized) {
            throw new KeyLockerException("WindowsKeyLocker not initialized");
        }

        try {
            return credManager.credentialExists(key);
        } catch (Exception e) {
            throw new KeyLockerException("Failed to check if credential exists", e);
        }
    }

    @Override
    public void initialize() throws KeyLockerException {
        if (!isSupported()) {
            throw new KeyLockerException("Windows platform is not supported on this system");
        }

        try {
            credManager.initialize(null); // Use default encryption key
            initialized = true;
        } catch (Exception e) {
            throw new KeyLockerException("Failed to initialize Windows credential manager", e);
        }
    }

    @Override
    public boolean isSupported() {
        return PlatformDetector.isWindows();
    }
}