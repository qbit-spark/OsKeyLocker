package platform.windows;

import com.OsSecureStore.SecureDataManager;
import com.OsSecureStore.exceptions.SecureStorageException;

import java.util.Map;

public class ExampleDataManager {

    public static void main(String[] args) {
        try {
            runExample();
        } catch (SecureStorageException ex) {
            System.err.println("Secure storage operation failed: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private static void runExample() throws SecureStorageException {
        // Create a manager with a namespace
        SecureDataManager authManager = new SecureDataManager("authentication");

        // Store individual credentials
        authManager.storeValue("github.username", "john.doe");
        authManager.storeValue("github.token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz");

        // Store OAuth tokens as a group
        Map<String, String> oauthTokens = SecureDataManager.createAuthCredentials(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", // access token
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  // refresh token
        );
        authManager.storeValueGroup("google", oauthTokens);

        // Retrieve credentials
        String username = authManager.loadValue("github.username");
        String accessToken = authManager.loadValue("google.access");

        System.out.println("GitHub username: " + username);
        System.out.println("Google access token: " + accessToken);

        // Check if a value exists
        boolean hasToken = authManager.hasValue("github.token");
        System.out.println("Has GitHub token: " + hasToken);

        // Remove a value
        authManager.removeValue("github.username");
    }
}