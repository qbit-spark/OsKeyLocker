package platform.windows;

import com.OsSecureStore.SecureDataManager;
import com.OsSecureStore.exceptions.SecureStorageException;

import java.util.Scanner;

public class TokenManagerAppTest {
    private static final SecureDataManager tokenManager = new SecureDataManager("api-tokens");

    public static void main(String[] args) {
        System.out.println("API Token Manager");
        System.out.println("================");

        try (Scanner scanner = new Scanner(System.in)) {
            boolean running = true;

            while (running) {
                System.out.println("\nOptions:");
                System.out.println("1. Add new token");
                System.out.println("2. View token");
                System.out.println("3. Remove token");
                System.out.println("4. List all tokens");
                System.out.println("5. Exit");
                System.out.print("\nEnter choice: ");

                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline

                switch (choice) {
                    case 1:
                        addToken(scanner);
                        break;
                    case 2:
                        viewToken(scanner);
                        break;
                    case 3:
                        removeToken(scanner);
                        break;
                    case 4:
                        listTokens();
                        break;
                    case 5:
                        running = false;
                        break;
                    default:
                        System.out.println("Invalid option!");
                }
            }

            System.out.println("Goodbye!");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void addToken(Scanner scanner) throws SecureStorageException {
        System.out.print("Enter service name (e.g., github): ");
        String service = scanner.nextLine();

        System.out.print("Enter token: ");
        String token = scanner.nextLine();

        tokenManager.storeValue(service, token);
        System.out.println("Token stored securely!");
    }

    private static void viewToken(Scanner scanner) throws SecureStorageException {
        System.out.print("Enter service name: ");
        String service = scanner.nextLine();

        String token = tokenManager.loadValue(service);
        if (token != null) {
            System.out.println("Token: " + token);
        } else {
            System.out.println("No token found for that service.");
        }
    }

    private static void removeToken(Scanner scanner) throws SecureStorageException {
        System.out.print("Enter service name: ");
        String service = scanner.nextLine();

        if (tokenManager.hasValue(service)) {
            tokenManager.removeValue(service);
            System.out.println("Token removed successfully!");
        } else {
            System.out.println("No token found for that service.");
        }
    }

    private static void listTokens() throws SecureStorageException {
        System.out.println("\nStored tokens:");

        // Note: In a real implementation, you would have a way to list all stored tokens
        // This is a simplified example that checks for common services
        String[] commonServices = {"github", "gitlab", "aws", "azure", "google"};
        boolean found = false;

        for (String service : commonServices) {
            if (tokenManager.hasValue(service)) {
                System.out.println("- " + service);
                found = true;
            }
        }

        if (!found) {
            System.out.println("No tokens found.");
        }
    }
}