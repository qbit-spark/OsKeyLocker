package com.OsSecureStore.platform;

import com.OsSecureStore.OsSecureStore;
import com.OsSecureStore.exceptions.SecureStorageException;


import java.util.HashMap;
import java.util.Map;

/**
 * SecureStorage - A cross-platform secure storage solution for sensitive application data
 */
public class SecureStorage {
    // Private constructor to force using builders
    private SecureStorage() {}

    /**
     * Creates a new write operation builder
     * @return A configured StorageWriter instance
     */
    public static StorageWriter write() {
        return new StorageWriter();
    }

    /**
     * Creates a new read operation builder
     * @return A configured StorageReader instance
     */
    public static StorageReader read() {
        return new StorageReader();
    }

    /**
     * Creates a new delete operation builder
     * @return A configured StorageDeleter instance
     */
    public static StorageDeleter delete() {
        return new StorageDeleter();
    }

    /**
     * Verify if secure storage is available on this platform
     * @return true if supported, false otherwise
     */
    public static boolean isSupported() {
        try {
            return OsSecureStore.isPlatformSupported();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Builder for write operations
     */
    public static class StorageWriter {
        private final OsSecureStore secureStore = new OsSecureStore();
        private final Map<String, Object> data = new HashMap<>();

        private StorageWriter() {}

        /**
         * Sets the encryption key for added security
         * @param key Custom encryption key
         * @return This builder instance
         */
        public StorageWriter withEncryption(String key) {
            secureStore.setEncryptionKey(key);
            return this;
        }

        /**
         * Sets the target identifier for this data
         * @param identifier Target identifier (e.g., "google-oauth", "aws-credentials")
         * @return This builder instance
         */
        public StorageWriter to(String identifier) {
            secureStore.setStorageKey(identifier);
            return this;
        }

        /**
         * Adds a single property to be stored
         * @param key Property key
         * @param value Property value
         * @return This builder instance
         */
        public StorageWriter property(String key, Object value) {
            data.put(key, value);
            return this;
        }

        /**
         * Adds multiple properties to be stored
         * @param properties Map of properties
         * @return This builder instance
         */
        public StorageWriter properties(Map<String, Object> properties) {
            data.putAll(properties);
            return this;
        }

        /**
         * Executes the write operation
         * @return Operation result status
         * @throws SecureStorageException if operation fails
         */
        public boolean execute() throws SecureStorageException {
            try {
                secureStore.setProperties(data).store();
                return true;
            } catch (SecureStorageException e) {
                throw new SecureStorageException("Failed to write secure data: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Builder for read operations
     */
    public static class StorageReader {
        private final OsSecureStore secureStore = new OsSecureStore();

        private StorageReader() {}

        /**
         * Sets the encryption key used when the data was stored
         * @param key Encryption key
         * @return This builder instance
         */
        public StorageReader withEncryption(String key) {
            secureStore.setEncryptionKey(key);
            return this;
        }

        /**
         * Sets the identifier to read from
         * @param identifier Target identifier (e.g., "google-oauth", "aws-credentials")
         * @return This builder instance
         */
        public StorageReader from(String identifier) {
            secureStore.setStorageKey(identifier);
            return this;
        }

        /**
         * Retrieves all properties stored under the specified identifier
         * @return Map of retrieved properties
         * @throws SecureStorageException if operation fails
         */
        public Map<String, Object> getAllProperties() throws SecureStorageException {
            try {
                Map<String, Object> result = secureStore.retrieve();
                return result != null ? result : new HashMap<>();
            } catch (SecureStorageException e) {
                throw new SecureStorageException("Failed to read secure data: " + e.getMessage(), e);
            }
        }

        /**
         * Retrieves a specific property from storage
         * @param key Property key to retrieve
         * @return The property value, or null if not found
         * @throws SecureStorageException if operation fails
         */
        public Object getProperty(String key) throws SecureStorageException {
            try {
                Map<String, Object> result = secureStore.retrieve();
                return result != null ? result.get(key) : null;
            } catch (SecureStorageException e) {
                throw new SecureStorageException("Failed to read secure data: " + e.getMessage(), e);
            }
        }

        /**
         * Checks if the specified identifier exists in secure storage
         * @return true if exists, false otherwise
         * @throws SecureStorageException if operation fails
         */
        public boolean exists() throws SecureStorageException {
            try {
                return secureStore.exists();
            } catch (SecureStorageException e) {
                throw new SecureStorageException("Failed to check existence: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Builder for delete operations
     */
    public static class StorageDeleter {
        private final OsSecureStore secureStore = new OsSecureStore();

        private StorageDeleter() {}

        /**
         * Sets the identifier to delete
         * @param identifier Target identifier to delete
         * @return This builder instance
         */
        public StorageDeleter identifier(String identifier) {
            secureStore.setStorageKey(identifier);
            return this;
        }

        /**
         * Executes the delete operation
         * @return Operation result status
         * @throws SecureStorageException if operation fails
         */
        public boolean execute() throws SecureStorageException {
            try {
                secureStore.remove();
                return true;
            } catch (SecureStorageException e) {
                throw new SecureStorageException("Failed to delete secure data: " + e.getMessage(), e);
            }
        }
    }
}