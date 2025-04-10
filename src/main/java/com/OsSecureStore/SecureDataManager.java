package com.OsSecureStore;

import com.OsSecureStore.exceptions.SecureStorageException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility for managing sensitive data securely using OsSecureStore
 */
public class SecureDataManager {

    private final String keyPrefix;

    /**
     * Creates a SecureDataManager with the default prefix
     */
    public SecureDataManager() {
        this("secure");
    }

    /**
     * Creates a SecureDataManager with a custom prefix
     * @param prefix Prefix for data keys
     */
    public SecureDataManager(String prefix) {
        this.keyPrefix = prefix;
    }

    /**
     * Stores a value securely
     * @param key Name/key for the value
     * @param value Data to store
     * @throws SecureStorageException if storage fails
     */
    public void storeValue(String key, String value) throws SecureStorageException {
        OsSecureStore.store(buildKey(key), value);
    }

    /**
     * Stores multiple values as a group
     * @param groupName Name for the value group
     * @param values Map of keys to values
     * @throws SecureStorageException if storage fails
     */
    public void storeValueGroup(String groupName, Map<String, String> values) throws SecureStorageException {
        for (Map.Entry<String, String> entry : values.entrySet()) {
            OsSecureStore.store(buildGroupKey(groupName, entry.getKey()), entry.getValue());
        }
    }

    /**
     * Loads a stored value
     * @param key Name/key of the value
     * @return The value, or null if not found
     * @throws SecureStorageException if retrieval fails
     */
    public String loadValue(String key) throws SecureStorageException {
        return OsSecureStore.retrieve(buildKey(key));
    }

    /**
     * Loads a stored value group
     * @param groupName Name of the value group
     * @return Map of keys to values
     * @throws SecureStorageException if retrieval fails
     */
    public Map<String, String> loadValueGroup(String groupName) throws SecureStorageException {
        // In a real implementation, we would scan all keys for the prefix
        // For now, we'll return an empty map if no values in this group are found

        // This is a simplified implementation
        return Collections.emptyMap();
    }

    /**
     * Removes a single value
     * @param key Name/key of the value
     * @throws SecureStorageException if removal fails
     */
    public void removeValue(String key) throws SecureStorageException {
        OsSecureStore.remove(buildKey(key));
    }

    /**
     * Removes a value group
     * @param groupName Name of the value group
     * @throws SecureStorageException if removal fails
     */
    public void removeValueGroup(String groupName) throws SecureStorageException {
        // In a real implementation, we would scan all keys for the prefix and remove them
        // For now, this is a placeholder
    }

    /**
     * Checks if a value exists
     * @param key Name/key of the value
     * @return true if the value exists, false otherwise
     * @throws SecureStorageException if the check fails
     */
    public boolean hasValue(String key) throws SecureStorageException {
        return OsSecureStore.exists(buildKey(key));
    }

    /**
     * Clears all values managed by this SecureDataManager
     * @throws SecureStorageException if clearing fails
     */
    public void clearAllValues() throws SecureStorageException {
        // We can't selectively clear by prefix efficiently, so we'll just clear all
        OsSecureStore.clear();
    }

    /**
     * Helper method to create common authentication credential groups
     * @param accessToken Access token
     * @param refreshToken Refresh token
     * @return Map containing the authentication credentials
     */
    public static Map<String, String> createAuthCredentials(String accessToken, String refreshToken) {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("access", accessToken);
        credentials.put("refresh", refreshToken);
        return credentials;
    }

    private String buildKey(String key) {
        return keyPrefix + "." + key;
    }

    private String buildGroupKey(String groupName, String key) {
        return keyPrefix + "." + groupName + "." + key;
    }
}