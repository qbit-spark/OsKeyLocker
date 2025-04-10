package com.OsSecureStore;

import com.OsSecureStore.exceptions.SecureStorageException;
import com.OsSecureStore.platform.PlatformSecureStorage;

import java.io.*;
import java.nio.file.*;
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

//    private static String detectApplicationName() {
//        // Analyze the call stack to find the calling application
//        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
//
//        // Find the first class that's not part of our library or Java itself
//        for (StackTraceElement element : stackTrace) {
//            String className = element.getClassName();
//
//            // Skip system and library classes
//            if (!className.startsWith("java.") &&
//                    !className.startsWith("javax.") &&
//                    !className.startsWith("sun.") &&
//                    !className.startsWith("com.OsSecureStore.")) {
//
//                try {
//                    // Load the class
//                    Class<?> callerClass = Class.forName(className);
//
//                    // Get the package name
//                    Package pkg = callerClass.getPackage();
//                    if (pkg != null) {
//                        // Use the first segment of the package name as the app name
//                        String packageName = pkg.getName();
//                        int firstDot = packageName.indexOf('.');
//
//                        if (firstDot > 0) {
//                            return packageName.substring(0, firstDot);
//                        } else {
//                            return packageName; // Use the whole package name if no dots
//                        }
//                    }
//
//                    // Fall back to class name if no package
//                    return callerClass.getSimpleName();
//
//                } catch (ClassNotFoundException e) {
//                    // Continue to the next element if this class can't be loaded
//                }
//            }
//        }
//
//        // If we get here, we couldn't find a suitable caller
//        return DEFAULT_APP_NAME;
//    }

    /**
     * Attempts to detect the application name from the calling application
     * @return Detected application name or default if detection fails
     */
    private static String detectApplicationName() {
        try {
            // First try to detect from main class
            String mainClass = System.getProperty("sun.java.command");
            if (mainClass != null && !mainClass.isEmpty()) {
                // Split by space to get the first part (main class name)
                String className = mainClass.split(" ")[0];
                if (className.contains(".")) {
                    // Extract package name
                    String packageName = className.substring(0, className.lastIndexOf("."));
                    if (!packageName.isEmpty()) {
                        // Get the first part of the package name
                        int firstDot = packageName.indexOf(".");
                        if (firstDot > 0) {
                            return packageName.substring(0, firstDot);
                        } else {
                            return packageName;
                        }
                    }
                } else {
                    // No package, use class name
                    return className;
                }
            }

            // If that fails, try stack trace analysis
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

            // Find the first class that's not part of our library or Java itself
            for (StackTraceElement element : stackTrace) {
                String className = element.getClassName();

                // Skip system and library classes
                if (!className.startsWith("java.") &&
                        !className.startsWith("javax.") &&
                        !className.startsWith("sun.") &&
                        !className.startsWith("com.OsSecureStore.") &&
                        !className.startsWith("jdk.")) {

                    try {
                        // Extract package name
                        int lastDot = className.lastIndexOf(".");
                        if (lastDot > 0) {
                            String packageName = className.substring(0, lastDot);

                            // Get top-level package
                            int firstDot = packageName.indexOf(".");
                            if (firstDot > 0) {
                                return packageName.substring(0, firstDot);
                            } else {
                                return packageName;
                            }
                        } else {
                            // No package, use class name
                            return className;
                        }
                    } catch (Exception e) {
                        // Continue to next element if there's an issue
                    }
                }
            }

            // If everything fails, try to get the current working directory name
            Path currentPath = Paths.get("").toAbsolutePath();
            String dirName = currentPath.getFileName().toString();
            if (dirName != null && !dirName.isEmpty()) {
                return dirName;
            }
        } catch (Exception e) {
            // Ignore exceptions in detection
        }


        // Last resort fallback
        return DEFAULT_APP_NAME;
    }
}