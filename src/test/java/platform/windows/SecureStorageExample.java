package platform.windows;

import com.OsKeyLocker.exceptions.KeyLockerException;
import com.OsKeyLocker.platform.KeyLocker;
import com.OsKeyLocker.util.EncryptionUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * Example demonstrating the use of SecureStorage
 */
public class SecureStorageExample {

    public static void main(String[] args) throws KeyLockerException {


            // Generate a random encryption key (or use a fixed one in production, but be careful with) hardcoding-- best way is to derive it from a password, or use a key management system)
            String encryptionKey = EncryptionUtil.generateEncryptionKey();
            System.out.println("Using encryption key: " + encryptionKey);

            // Example 1: Store OAuth credentials
            storeOAuthCredentials(encryptionKey);

            // Example 2: Store API keys
            storeApiKey(encryptionKey);

            // Example 3: Retrieve and use credentials
            retrieveAndUseCredentials(encryptionKey);

            // Example 4: Delete credentials when no longer needed
            deleteCredentials();

    }

    private static void storeOAuthCredentials(String encryptionKey) throws KeyLockerException {
        System.out.println("\n=== Storing OAuth Credentials ===");

        // Create OAuth credentials
        Map<String, Object> oauth = new HashMap<>();
        oauth.put("access_token", "eyJ0eXAiOiJKV1QiLCJhbGc...");
        oauth.put("refresh_token", "eyJhbGciOiJIUzI1NiIsInR5cCI...");
        oauth.put("expires_in", 3600);
        oauth.put("token_type", "Bearer");
        oauth.put("description", "This is a large credential that will need to be chunked when stored, This is a large credential that will need to be chunked when stored, This is a large credential that will need to be chunked when stored,This is a large credential that will need to be chunked when stored,This is a large credential that will need to be chunked when stored");

        // Add many fields with random UUIDs to increase size
//        for (int i = 0; i < 50; i++) {
//            oauth.put("field" + i, UUID.randomUUID().toString().repeat(10));
//        }

        // Store the credentials
        boolean success = KeyLocker.write()
                .withEncryption(encryptionKey)
                .to("google-oauth")
                .properties(oauth)
                .execute();

        System.out.println("OAuth credentials stored successfully: " + success);
    }

    private static void storeApiKey(String encryptionKey) throws KeyLockerException {
        System.out.println("\n=== Storing API Keys ===");

        // Store individual API keys
        boolean success = KeyLocker.write()
                .withEncryption(encryptionKey)
                .to("github-api")
                .property("key", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
                .property("username", "myusername")
                .execute();

        System.out.println("API key stored successfully: " + success);
    }

    private static void retrieveAndUseCredentials(String encryptionKey) throws KeyLockerException {
        System.out.println("\n=== Retrieving Credentials ===");

        // Check if credentials exist
        boolean oauthExists = KeyLocker.read()
                .withEncryption(encryptionKey)
                .from("google-oauth")
                .exists();

        System.out.println("OAuth credentials exist: " + oauthExists);

        if (oauthExists) {
            // Retrieve all OAuth properties
            Map<String, Object> credentials = KeyLocker.read()
                    .withEncryption(encryptionKey)
                    .from("google-oauth")
                    .getAllProperties();

            System.out.println("Retrieved OAuth credentials:");
            for (Map.Entry<String, Object> entry : credentials.entrySet()) {
                System.out.println("  " + entry.getKey() + ": " + entry.getValue());
            }

            // Retrieve specific property
            String accessToken = (String) KeyLocker.read()
                    .withEncryption(encryptionKey)
                    .from("google-oauth")
                    .getProperty("access_token");

            System.out.println("\nAccess token: " + accessToken);
        }

        // Get GitHub API key
        String apiKey = (String) KeyLocker.read()
                .withEncryption(encryptionKey)
                .from("github-api")
                .getProperty("key");

        System.out.println("GitHub API key: " + apiKey);
    }

    private static void deleteCredentials() throws KeyLockerException {
        System.out.println("\n=== Deleting Credentials ===");

        // Delete OAuth credentials
        boolean success = KeyLocker.delete()
                .identifier("google-oauth")
                .execute();

        System.out.println("OAuth credentials deleted: " + success);

        // Delete API key
        success = KeyLocker.delete()
                .identifier("github-api")
                .execute();

        System.out.println("API key deleted: " + success);
    }
}