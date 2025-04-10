package platform.windows;

import com.OsSecureStore.OsSecureStore;
import com.OsSecureStore.SecureDataManager;
import com.OsSecureStore.exceptions.SecureStorageException;

import java.util.Map;

public class WindowsSecureStorageTest {
    public static void main(String[] args) {
        // Set a fixed application name for tests
        OsSecureStore.setApplicationName("OsSecureStoreTest");

        try {
            // Test basic OsSecureStore operations
            System.out.println("===== Testing OsSecureStore =====");
            testBasicOperations();

            // Test SecureDataManager
            System.out.println("\n===== Testing SecureDataManager =====");
            testSecureDataManager();

            // Test group operations
            System.out.println("\n===== Testing Group Operations =====");
            testGroupOperations();

            // Test edge cases
            System.out.println("\n===== Testing Edge Cases =====");
            testEdgeCases();

            // Clean up after all tests
            OsSecureStore.clear();
            System.out.println("\n===== All tests completed successfully =====");

        } catch (SecureStorageException e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void testBasicOperations() throws SecureStorageException {
        // Store a single value
        OsSecureStore.store("test.key", "test-value-123");
        System.out.println("Stored a test key");

        // Check if the key exists
        boolean exists = OsSecureStore.exists("test.key");
        System.out.println("Key exists: " + exists);

        // Retrieve the value
        String value = OsSecureStore.retrieve("test.key");
        System.out.println("Retrieved value: " + value);
        assert "test-value-123".equals(value) : "Retrieved value doesn't match stored value";

        // Remove the value
        OsSecureStore.remove("test.key");
        System.out.println("Removed the test key");

        // Verify it was removed
        exists = OsSecureStore.exists("test.key");
        System.out.println("Key exists after removal: " + exists);
        assert !exists : "Key should not exist after removal";
    }

    private static void testSecureDataManager() throws SecureStorageException {
        // Create a SecureDataManager with custom prefix
        SecureDataManager manager = new SecureDataManager("test-manager");

        // Store values
        manager.storeValue("username", "test-user");
        manager.storeValue("password", "test-password");
        System.out.println("Stored username and password");

        // Retrieve values
        String username = manager.loadValue("username");
        String password = manager.loadValue("password");
        System.out.println("Retrieved username: " + username);
        System.out.println("Retrieved password: " + password);
        assert "test-user".equals(username) : "Username doesn't match";
        assert "test-password".equals(password) : "Password doesn't match";

        // Check if values exist
        boolean hasUsername = manager.hasValue("username");
        boolean hasApiKey = manager.hasValue("api-key");
        System.out.println("Has username: " + hasUsername);
        System.out.println("Has API key: " + hasApiKey);
        assert hasUsername : "Username should exist";
        assert !hasApiKey : "API key should not exist";

        // Remove a value
        manager.removeValue("username");
        System.out.println("Removed username");

        // Verify it was removed
        hasUsername = manager.hasValue("username");
        System.out.println("Has username after removal: " + hasUsername);
        assert !hasUsername : "Username should not exist after removal";

        // Clean up
        manager.clearAllValues();
        System.out.println("Cleared all values");
    }

    private static void testGroupOperations() throws SecureStorageException {
        // Create a SecureDataManager
        SecureDataManager manager = new SecureDataManager("group-test");

        // Create credential group
        Map<String, String> credentials = SecureDataManager.createAuthCredentials(
                "access-token-123",
                "refresh-token-456"
        );
        System.out.println("Created credential group");

        // Store the group
        manager.storeValueGroup("oauth", credentials);
        System.out.println("Stored credential group");

        // Retrieve individual values from the group
        String accessToken = manager.loadValue("oauth.access");
        String refreshToken = manager.loadValue("oauth.refresh");
        System.out.println("Retrieved access token: " + accessToken);
        System.out.println("Retrieved refresh token: " + refreshToken);
        assert "access-token-123".equals(accessToken) : "Access token doesn't match";
        assert "refresh-token-456".equals(refreshToken) : "Refresh token doesn't match";

        // Test loading the whole group
        Map<String, String> loadedGroup = manager.loadValueGroup("oauth");
        System.out.println("Loaded entire group: " + loadedGroup);

        // Remove the group
        manager.removeValueGroup("oauth");
        System.out.println("Removed credential group");

        // Verify group was removed
        boolean hasAccess = manager.hasValue("oauth.access");
        System.out.println("Has access token after removal: " + hasAccess);
        assert !hasAccess : "Access token should not exist after group removal";
    }

    private static void testEdgeCases() throws SecureStorageException {
        // Test storing empty values
        OsSecureStore.store("empty.key", "");
        String emptyValue = OsSecureStore.retrieve("empty.key");
        System.out.println("Empty value test: " + (emptyValue.isEmpty() ? "passed" : "failed"));
        assert emptyValue.isEmpty() : "Empty value should be retrieved as empty";

        // Test storing special characters
        String specialChars = "!@#$%^&*()_+{}[]|\"':;,.<>?/~`";
        OsSecureStore.store("special.chars", specialChars);
        String retrievedSpecial = OsSecureStore.retrieve("special.chars");
        System.out.println("Special chars test: " + (specialChars.equals(retrievedSpecial) ? "passed" : "failed"));
        assert specialChars.equals(retrievedSpecial) : "Special characters should be preserved";

        // Test storing longer text
        StringBuilder longText = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longText.append("Long text test. ");
        }
        OsSecureStore.store("long.text", longText.toString());
        String retrievedLongText = OsSecureStore.retrieve("long.text");
        boolean longTextMatch = longText.toString().equals(retrievedLongText);
        System.out.println("Long text test: " + (longTextMatch ? "passed" : "failed"));
        assert longTextMatch : "Long text should be preserved";

        // Test retrieving non-existent key
        String nonExistent = OsSecureStore.retrieve("non.existent.key");
        System.out.println("Non-existent key test: " + (nonExistent == null ? "passed" : "failed"));
        assert nonExistent == null : "Non-existent key should return null";

        // Test overwriting existing key
        OsSecureStore.store("overwrite.key", "original");
        OsSecureStore.store("overwrite.key", "overwritten");
        String overwritten = OsSecureStore.retrieve("overwrite.key");
        System.out.println("Overwrite test: " + ("overwritten".equals(overwritten) ? "passed" : "failed"));
        assert "overwritten".equals(overwritten) : "Overwritten value should be retrieved";

        // Clean up edge case tests
        OsSecureStore.remove("empty.key");
        OsSecureStore.remove("special.chars");
        OsSecureStore.remove("long.text");
        OsSecureStore.remove("overwrite.key");
    }
}