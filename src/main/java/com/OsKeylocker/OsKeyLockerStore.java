package com.OsKeylocker;

import com.OsKeylocker.exceptions.OsKeylockerExceptionException;
import com.OsKeylocker.platform.PlatformKeylocker;
import com.OsKeylocker.platform.windows.WindowsKeylocker;
import com.OsKeylocker.util.PackageDetector;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * Internal implementation of secure storage operations
 * Not intended for direct use - use SecureStorage class instead
 */
public class OsKeyLockerStore {

    private static final String DEFAULT_ENCRYPTION_KEY = "OsKeylocker-DefaultKey-DoNotUse";
    private static String encryptionKey = DEFAULT_ENCRYPTION_KEY;
    private static String storageKey = "default";
    private Map<String, Object> properties;
    private static String appPackageName;
    private static PlatformKeylocker platformStorage;

    static {
        try {
            platformStorage = SecureStorageFactory.getSecureStorage();
            appPackageName = PackageDetector.detectCallingPackage();
            ((WindowsKeylocker) platformStorage).initialize(appPackageName, DEFAULT_ENCRYPTION_KEY);
        } catch (OsKeylockerExceptionException e) {
            System.err.println("Error initializing secure storage: " + e.getMessage());
        }
    }

    /**
     * Creates a new OsKeylocker store instance
     */
    public OsKeyLockerStore() {
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
    public OsKeyLockerStore setEncryptionKey(String key) {
        this.encryptionKey = key;
        return this;
    }

    /**
     * Sets the storage key
     * @param key The storage key to use
     * @return This instance for chaining
     */
    public OsKeyLockerStore setStorageKey(String key) {
        this.storageKey = key;
        return this;
    }

    /**
     * Sets the properties to store
     * @param properties Map of properties to store
     * @return This instance for chaining
     */
    public OsKeyLockerStore setProperties(Map<String, Object> properties) {
        this.properties = properties;
        return this;
    }

    /**
     * Stores the properties using the configured settings
     * @return This instance for chaining
     * @throws OsKeylockerExceptionException if storage fails
     */
    public  OsKeyLockerStore store() throws OsKeylockerExceptionException {
        if (properties == null || properties.isEmpty()) {
            throw new OsKeylockerExceptionException("No properties to store");
        }

        if (platformStorage == null) {
            throw new OsKeylockerExceptionException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsKeylocker) {
            // Update encryption key if needed
            if (!encryptionKey.equals(DEFAULT_ENCRYPTION_KEY)) {
                ((WindowsKeylocker) platformStorage).setEncryptionKey(encryptionKey);
            }

            // Convert properties to JSONObject
            JSONObject data = new JSONObject();
            for (Map.Entry<String, Object> entry : properties.entrySet()) {
                data.put(entry.getKey(), entry.getValue());
            }

            // Store the data
            ((WindowsKeylocker) platformStorage).storeJsonCredential(storageKey, data);
        } else {
            throw new OsKeylockerExceptionException("Platform not supported");
        }

        return this;
    }

    /**
     * Retrieves stored properties
     * @return Map of stored properties
     * @throws OsKeylockerExceptionException if retrieval fails
     */
    public static Map<String, Object> retrieve() throws OsKeylockerExceptionException {
        if (platformStorage == null) {
            throw new OsKeylockerExceptionException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsKeylocker) {
            // Update encryption key if needed
            if (!encryptionKey.equals(DEFAULT_ENCRYPTION_KEY)) {
                ((WindowsKeylocker) platformStorage).setEncryptionKey(encryptionKey);
            }

            try {
                JSONObject data = ((WindowsKeylocker) platformStorage).retrieveJsonCredential(storageKey);
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
                throw new OsKeylockerExceptionException("Failed to retrieve properties", e);
            }
        } else {
            throw new OsKeylockerExceptionException("Platform not supported");
        }
    }

    /**
     * Removes stored properties
     * @return This instance for chaining
     * @throws OsKeylockerExceptionException if removal fails
     */
    public OsKeyLockerStore remove() throws OsKeylockerExceptionException {
        if (platformStorage == null) {
            throw new OsKeylockerExceptionException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsKeylocker) {
            ((WindowsKeylocker) platformStorage).removeCredential(storageKey);
        } else {
            throw new OsKeylockerExceptionException("Platform not supported");
        }

        return this;
    }

    /**
     * Checks if properties exist for the current storage key
     * @return true if properties exist, false otherwise
     * @throws OsKeylockerExceptionException if the check fails
     */
    public boolean exists() throws OsKeylockerExceptionException {
        if (platformStorage == null) {
            throw new OsKeylockerExceptionException("Secure storage not initialized");
        }

        if (platformStorage instanceof WindowsKeylocker) {
            return ((WindowsKeylocker) platformStorage).credentialExists(storageKey);
        } else {
            throw new OsKeylockerExceptionException("Platform not supported");
        }
    }
}