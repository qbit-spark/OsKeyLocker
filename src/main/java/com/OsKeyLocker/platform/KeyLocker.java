package com.OsKeyLocker.platform;



import com.OsKeyLocker.KeyLockerStore;
import com.OsKeyLocker.exceptions.KeyLockerException;

import java.util.HashMap;
import java.util.Map;

/**
 * SecureStorage - A cross-platform secure storage solution for sensitive application data
 */

public class KeyLocker {
    private KeyLocker() {}

    /**
     * Creates a new write operation builder
     * @return A builder that requires encryption to be set
     */
    public static EncryptionWriteStep write() {
        return new StorageWriterImpl();
    }

    /**
     * Creates a new read operation builder
     * @return A builder that requires encryption to be set
     */
    public static EncryptionReadStep read() {
        return new StorageReaderImpl();
    }

    // Delete operation can remain the same
    public static StorageDeleter delete() {
        return new StorageDeleter();
    }

    // Interfaces for enforcing the build steps

    /**
     * First step of write operation: Setting encryption
     */
    public interface EncryptionWriteStep {
        /**
         * Required: Sets the encryption key for secure storage
         * @param key Custom encryption key
         * @return Next step for destination selection
         */
        DestinationWriteStep withEncryption(String key);
    }

    /**
     * Second step of write operation: Setting destination
     */
    public interface DestinationWriteStep {
        /**
         * Required: Sets the target identifier for this data
         * @param identifier Target identifier (e.g., "google-oauth", "aws-credentials")
         * @return Final builder for adding properties and execution
         */
        StorageWriter to(String identifier);
    }

    /**
     * First step of read operation: Setting encryption
     */
    public interface EncryptionReadStep {
        /**
         * Required: Sets the encryption key for secure retrieval
         * @param key Encryption key used when storing the data
         * @return Next step for source selection
         */
        SourceReadStep withEncryption(String key);
    }

    /**
     * Second step of read operation: Setting source
     */
    public interface SourceReadStep {
        /**
         * Required: Sets the identifier to read from
         * @param identifier Target identifier (e.g., "google-oauth", "aws-credentials")
         * @return Final builder for retrieving properties
         */
        StorageReader from(String identifier);
    }

    // Implementations

    /**
     * Implementation of the write operation builder
     */
    private static class StorageWriterImpl implements EncryptionWriteStep, DestinationWriteStep, StorageWriter {
        private final KeyLockerStore secureStore = new KeyLockerStore();
        private final Map<String, Object> data = new HashMap<>();

        @Override
        public DestinationWriteStep withEncryption(String key) {
            secureStore.setEncryptionKey(key);
            return this;
        }

        @Override
        public StorageWriter to(String identifier) {
            secureStore.setStorageKey(identifier);
            return this;
        }

        @Override
        public StorageWriter property(String key, Object value) {
            data.put(key, value);
            return this;
        }

        @Override
        public StorageWriter properties(Map<String, Object> properties) {
            data.putAll(properties);
            return this;
        }

        @Override
        public boolean execute() throws KeyLockerException {
            try {
                secureStore.setProperties(data).store();
                return true;
            } catch (KeyLockerException e) {
                throw new KeyLockerException("Failed to write secure data: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Implementation of the read operation builder okay
     */
    private static class StorageReaderImpl implements EncryptionReadStep, SourceReadStep, StorageReader {
        private final KeyLockerStore secureStore = new KeyLockerStore();

        @Override
        public SourceReadStep withEncryption(String key) {
            secureStore.setEncryptionKey(key);
            return this;
        }

        @Override
        public StorageReader from(String identifier) {
            secureStore.setStorageKey(identifier);
            return this;
        }

        @Override
        public Map<String, Object> getAllProperties() throws KeyLockerException {
            try {
                Map<String, Object> result = secureStore.retrieve();
                return result != null ? result : new HashMap<>();
            } catch (KeyLockerException e) {
                throw new KeyLockerException("Failed to read secure data: " + e.getMessage(), e);
            }
        }

        @Override
        public Object getProperty(String key) throws KeyLockerException {
            try {
                Map<String, Object> result = secureStore.retrieve();
                return result != null ? result.get(key) : null;
            } catch (KeyLockerException e) {
                throw new KeyLockerException("Failed to read secure data: " + e.getMessage(), e);
            }
        }

        @Override
        public boolean exists() throws KeyLockerException {
            try {
                return secureStore.exists();
            } catch (KeyLockerException e) {
                throw new KeyLockerException("Failed to check existence: " + e.getMessage(), e);
            }
        }
    }

    // Define public interfaces for the final builder stages

    /**
     * Builder for write operations
     */
    public interface StorageWriter {
        /**
         * Adds a single property to be stored
         * @param key Property key
         * @param value Property value
         * @return This builder instance
         */
        StorageWriter property(String key, Object value);

        /**
         * Adds multiple properties to be stored
         * @param properties Map of properties
         * @return This builder instance
         */
        StorageWriter properties(Map<String, Object> properties);

        /**
         * Executes the write operation
         * @return Operation result status
         * @throws KeyLockerException if operation fails
         */
        boolean execute() throws KeyLockerException;
    }

    /**
     * Builder for read operations
     */
    public interface StorageReader {
        /**
         * Retrieves all properties stored under the specified identifier
         * @return Map of retrieved properties
         * @throws KeyLockerException if operation fails
         */
        Map<String, Object> getAllProperties() throws KeyLockerException;

        /**
         * Retrieves a specific property from storage
         * @param key Property key to retrieve
         * @return The property value, or null if not found
         * @throws KeyLockerException if operation fails
         */
        Object getProperty(String key) throws KeyLockerException;

        /**
         * Checks if the specified identifier exists in secure storage
         * @return true if exists, false otherwise
         * @throws KeyLockerException if operation fails
         */
        boolean exists() throws KeyLockerException;
    }

    /**
     * Builder for delete operations
     */
    public static class StorageDeleter {
        private final KeyLockerStore secureStore = new KeyLockerStore();

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
         * @throws KeyLockerException if operation fails
         */
        public boolean execute() throws KeyLockerException {
            try {
                secureStore.remove();
                return true;
            } catch (KeyLockerException e) {
                throw new KeyLockerException("Failed to delete secure data: " + e.getMessage(), e);
            }
        }
    }
}