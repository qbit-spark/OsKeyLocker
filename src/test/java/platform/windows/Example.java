package platform.windows;

import com.OsSecureStore.OsSecureStore;
import com.OsSecureStore.exceptions.SecureStorageException;

public class Example {
    public static void main(String[] args) {
        try {
            // Set application name
            OsSecureStore.setApplicationName("ExampleApp");

            // Use the same key consistently
            String credentialKey = "api.github";

            // Store an API key
            OsSecureStore.store(credentialKey, "ghp_1234567890abcdefghijklmnopqrstuvwxyz");
            System.out.println("API key stored successfully!");

            // Retrieve the API key
            String apiKey = OsSecureStore.retrieve(credentialKey);
            if (apiKey != null) {
                System.out.println("Retrieved API key: " + apiKey);
            } else {
                System.out.println("API key not found!");
            }

            // Check if credential exists
            boolean exists = OsSecureStore.exists(credentialKey);
            System.out.println("API key exists: " + exists);

            // Remove the credentials
            // OsSecureStore.remove(credentialKey);
            // System.out.println("API key removed successfully!");

            // Check if credential exists after remove
            // exists = OsSecureStore.exists(credentialKey);
            // System.out.println("API key exists after removal: " + exists);

        } catch (SecureStorageException e) {
            System.err.println("Error managing credentials: " + e.getMessage());
            e.printStackTrace();
        }
    }
}