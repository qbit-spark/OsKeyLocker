package com.OsKeyLocker;

import com.OsKeyLocker.exceptions.KeyLockerException;
import com.OsKeyLocker.platform.PlatformKeyLockerStorage;
import com.OsKeyLocker.platform.windows.WindowsSecureStorage;
import com.OsKeyLocker.util.PackageDetector;
import org.json.JSONObject;


import java.util.HashMap;
import java.util.Map;

/**
 * Internal implementation of secure storage operations
 * Not intended for direct use - use SecureStorage class instead
 */
public class KeyLockerStore {

    //Till now, we have not seen the necessary to use hardcoded the encryption key
    private static final String DEFAULT_ENCRYPTION_KEY = "OsSecureStore-DefaultKey-DoNotUse";
    private static String encryptionKey = DEFAULT_ENCRYPTION_KEY;
    private static String storageKey = "default";
    private Map<String, Object> properties;
    private static String appPackageName;
    private static PlatformKeyLockerStorage platformStorage;

    static {
        try {
            platformStorage = KeyLockerStoreFactory.getSecureStorage();
            appPackageName = PackageDetector.detectCallingPackage();
            ((WindowsSecureStorage) platformStorage).initialize(appPackageName, DEFAULT_ENCRYPTION_KEY);
        } catch (KeyLockerException e) {
            System.err.println("Error initializing secure storage: " + e.getMessage());
        }
    }

    /**
     * Creates a new OsSecureStore instance
     */
    public KeyLockerStore() {
        // Constructor intentionally package-private
    }

    /**
     * Check if secure storage is supported on this platform
     * @return true if supported, false otherwise
     */
    public static boolean isPlatformSupported() {
        return platformStorage != null && platformStorage.isSupported();
    }

    /**
     * Sets the encryption key
     * @param key The encryption key to use
     * @return This instance for chaining
     */
    public KeyLockerStore setEncryptionKey(String key) {
        this.encryptionKey = key;
        return this;
    }

    /**
     * Sets the storage key
     * @param key The storage key to use
     * @return This instance for chaining
     */
    public KeyLockerStore setStorageKey(String key) {
        this.storageKey = key;
        return this;
    }

    /**
     * Sets the properties to store
     * @param properties Map of properties to store
     * @return This instance for chaining
     */
    public KeyLockerStore setProperties(Map<String, Object> properties) {
        this.properties = properties;
        return this;
    }

    /**
     * Stores the properties using the configured settings
     * @return This instance for chaining
     * @throws KeyLockerException if storage fails
     */
    public  KeyLockerStore store() throws KeyLockerException {
        if (properties == null || properties.isEmpty()) {
            throw new KeyLockerException("No properties to store");
        }

        if (platformStorage == null) {
            throw new KeyLockerException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            // Update encryption key if needed
            if (!encryptionKey.equals(DEFAULT_ENCRYPTION_KEY)) {
                ((WindowsSecureStorage) platformStorage).setEncryptionKey(encryptionKey);
            }

            // Convert properties to JSONObject
            JSONObject data = new JSONObject();
            for (Map.Entry<String, Object> entry : properties.entrySet()) {
                data.put(entry.getKey(), entry.getValue());
            }

            // Store the data
            ((WindowsSecureStorage) platformStorage).storeJsonCredential(storageKey, data);
        } else {
            throw new KeyLockerException("Platform not supported");
        }

        return this;
    }

    /**
     * Retrieves stored properties
     * @return Map of stored properties
     * @throws KeyLockerException if retrieval fails
     */
    public static Map<String, Object> retrieve() throws KeyLockerException {
        if (platformStorage == null) {
            throw new KeyLockerException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            // Update encryption key if needed
            if (!encryptionKey.equals(DEFAULT_ENCRYPTION_KEY)) {
                ((WindowsSecureStorage) platformStorage).setEncryptionKey(encryptionKey);
            }

            try {
                JSONObject data = ((WindowsSecureStorage) platformStorage).retrieveJsonCredential(storageKey);
                if (data == null) {
                    return null;
                }

                // Convert JSONObject to Map
                Map<String, Object> result = new HashMap<>();
                for (String key : data.keySet()) {
                    result.put(key, data.get(key));
                }
                return result;
            } catch (Exception e) {
                if (e.getMessage().contains("not found")) {
                    return null;
                }
                throw new KeyLockerException("Failed to retrieve properties", e);
            }
        } else {
            throw new KeyLockerException("Platform not supported");
        }
    }

    /**
     * Removes stored properties
     * @return This instance for chaining
     * @throws KeyLockerException if removal fails
     */
    public KeyLockerStore remove() throws KeyLockerException {
        if (platformStorage == null) {
            throw new KeyLockerException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            ((WindowsSecureStorage) platformStorage).removeCredential(storageKey);
        } else {
            throw new KeyLockerException("Platform not supported");
        }

        return this;
    }

    /**
     * Checks if properties exist for the current storage key
     * @return true if properties exist, false otherwise
     * @throws KeyLockerException if the check fails
     */
    public boolean exists() throws KeyLockerException {
        if (platformStorage == null) {
            throw new KeyLockerException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            return ((WindowsSecureStorage) platformStorage).credentialExists(storageKey);
        } else {
            throw new KeyLockerException("Platform not supported");
        }
    }
}