package com.OsSecureStore;

import com.OsSecureStore.exceptions.SecureStorageException;
import com.OsSecureStore.platform.PlatformSecureStorage;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

/**
 * Main API for OsSecureStore
 * Provides methods for securely storing and retrieving data
 */
public class OsSecureStore {

    private static final String DEFAULT_APP_NAME = "OsSecureStore";
    private static String appName = null;
    private static Path storageDir;
    private static PlatformSecureStorage platformStorage;

    static {
        try {
            platformStorage = SecureStorageFactory.getSecureStorage();
            platformStorage.initialize();

            // Set default storage location
            setDefaultStorageLocation();
        } catch (SecureStorageException e) {
            // Will be thrown when methods are called
        }
    }

    /**
     * Sets the application name used for storage
     * Only needed if automatic detection doesn't work or needs to be overridden
     * @param name Application name
     */
    public static void setApplicationName(String name) {
        appName = name;
        setDefaultStorageLocation();
    }


    /**
     * Sets a custom storage location
     * @param directory Custom directory path
     */
    public static void setStorageLocation(String directory) {
        storageDir = Paths.get(directory);
        createStorageDirectoryIfNeeded();
    }

    /**
     * Securely stores a value with the given key
     * @param key Key to associate with the value
     * @param value Value to store
     * @throws SecureStorageException if storage fails
     */
    public static void store(String key, String value) throws SecureStorageException {
        try {
            if (platformStorage == null) {
                throw new SecureStorageException("Secure storage not initialized");
            }

            // Encrypt the value
            byte[] encryptedData = platformStorage.encrypt(value.getBytes());
            String encodedData = Base64.getEncoder().encodeToString(encryptedData);

            // Store in properties file
            Properties props = loadProperties();
            props.setProperty(key, encodedData);
            saveProperties(props);
        } catch (IOException e) {
            throw new SecureStorageException("Failed to store value", e);
        }
    }




    /**
     * Retrieves a securely stored value
     * @param key Key associated with the value
     * @return The retrieved value, or null if not found
     * @throws SecureStorageException if retrieval fails
     */
    public static String retrieve(String key) throws SecureStorageException {
        try {
            if (platformStorage == null) {
                throw new SecureStorageException("Secure storage not initialized");
            }

            Properties props = loadProperties();
            String encodedData = props.getProperty(key);

            if (encodedData == null) {
                return null;
            }

            // Decode and decrypt
            byte[] encryptedData = Base64.getDecoder().decode(encodedData);
            byte[] decryptedData = platformStorage.decrypt(encryptedData);

            return new String(decryptedData);
        } catch (IOException e) {
            throw new SecureStorageException("Failed to retrieve value", e);
        }
    }

    /**
     * Removes a value from secure storage
     * @param key Key to remove
     * @throws SecureStorageException if removal fails
     */
    public static void remove(String key) throws SecureStorageException {
        try {
            Properties props = loadProperties();
            props.remove(key);
            saveProperties(props);
        } catch (IOException e) {
            throw new SecureStorageException("Failed to remove value", e);
        }
    }

    /**
     * Checks if a key exists in secure storage
     * @param key Key to check
     * @return true if the key exists, false otherwise
     * @throws SecureStorageException if the check fails
     */
    public static boolean exists(String key) throws SecureStorageException {
        try {
            Properties props = loadProperties();
            return props.containsKey(key);
        } catch (IOException e) {
            throw new SecureStorageException("Failed to check if key exists", e);
        }
    }

    /**
     * Clears all stored values
     * @throws SecureStorageException if clearing fails
     */
    public static void clear() throws SecureStorageException {
        try {
            Files.deleteIfExists(getPropertiesPath());
        } catch (IOException e) {
            throw new SecureStorageException("Failed to clear secure storage", e);
        }
    }

    private static void setDefaultStorageLocation() {
        // Auto-detect application name if not specified
        if (appName == null) {
            appName = detectApplicationName();
            System.out.println("Detected application name: " + appName);
        }


        String osName = System.getProperty("os.name").toLowerCase();
        String userHome = System.getProperty("user.home");

        if (osName.contains("win")) {
            // Windows: %APPDATA%\AppName
            String appData = System.getenv("APPDATA");
            if (appData == null) {
                appData = userHome + "\\AppData\\Roaming";
            }
            storageDir = Paths.get(appData, appName);
        } else if (osName.contains("mac")) {
            // macOS: ~/Library/Application Support/AppName
            storageDir = Paths.get(userHome, "Library", "Application Support", appName);
        } else {
            // Linux/Unix: ~/.config/AppName
            storageDir = Paths.get(userHome, ".config", appName);
        }

        createStorageDirectoryIfNeeded();
    }

    private static void createStorageDirectoryIfNeeded() {
        try {
            if (!Files.exists(storageDir)) {
                Files.createDirectories(storageDir);
            }
        } catch (IOException e) {
            // Will be handled when storage methods are called
        }
    }

    private static Path getPropertiesPath() {
        return storageDir.resolve("secure-storage.properties");
    }

    private static Properties loadProperties() throws IOException {
        Properties props = new Properties();
        Path path = getPropertiesPath();

        if (Files.exists(path)) {
            try (InputStream in = Files.newInputStream(path)) {
                props.load(in);
            }
        }

        return props;
    }

    private static void saveProperties(Properties props) throws IOException {
        Path path = getPropertiesPath();

        try (OutputStream out = Files.newOutputStream(path)) {
            props.store(out, "OsSecureStore encrypted data");
        }
    }

    /**
     * Attempts to detect the application name from the calling application
     * @return Detected application name or default if detection fails
     */

    private static String detectApplicationName() {
        try {
            // First try to get the JAR file path - most reliable for deployed applications
            try {
                String jarPath = OsSecureStore.class
                        .getProtectionDomain()
                        .getCodeSource()
                        .getLocation()
                        .toURI()
                        .getPath();

                // Extract JAR filename
                String jarName = jarPath.substring(jarPath.lastIndexOf("/") + 1);

                // Remove .jar extension if present
                if (jarName.toLowerCase().endsWith(".jar")) {
                    jarName = jarName.substring(0, jarName.length() - 4);
                }

                // Use the JAR name as app name if it's not our own library
                if (!jarName.toLowerCase().contains("ossecurestore")) {
                    return jarName;
                }
            } catch (Exception e) {
                // Fall through to other methods if JAR detection fails
            }

            // Try to get the main class name
            String mainClass = System.getProperty("sun.java.command");
            if (mainClass != null && !mainClass.isEmpty()) {
                if (mainClass.contains(" ")) {
                    mainClass = mainClass.split(" ")[0]; // Remove arguments
                }

                // Use the full main class name as a unique identifier
                if (!mainClass.startsWith("com.OsSecureStore")) {
                    return "app-" + mainClass.replace('.', '-');
                }
            }

            // If main class detection fails, create a hash-based ID from the classpath
            String classpath = System.getProperty("java.class.path");
            if (classpath != null && !classpath.isEmpty()) {
                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] hash = md.digest(classpath.getBytes());
                    // Use the first 8 chars of the hash
                    String hashId = bytesToHex(hash).substring(0, 8);
                    return "app-" + hashId;
                } catch (NoSuchAlgorithmException e) {
                    // Fall through to next method if hashing fails
                }
            }

            // Try using a combination of user.dir and user.name for uniqueness
            String userDir = System.getProperty("user.dir");
            String userName = System.getProperty("user.name");
            if (userDir != null && userName != null) {
                String combined = userDir + userName;
                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] hash = md.digest(combined.getBytes());
                    // Use the first 8 chars of the hash
                    String hashId = bytesToHex(hash).substring(0, 8);
                    return "app-" + hashId;
                } catch (NoSuchAlgorithmException e) {
                    // Fall back to using the directory name if hashing fails
                    Path path = Paths.get(userDir);
                    return "app-" + path.getFileName().toString();
                }
            }
        } catch (Exception e) {
            // Ignore errors in detection
        }

        // Ultimate fallback with timestamp to ensure uniqueness
        return "ossecurestore-" + System.currentTimeMillis();
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}