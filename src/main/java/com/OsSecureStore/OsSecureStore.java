package com.OsSecureStore;

import com.OsSecureStore.exceptions.SecureStorageException;
import com.OsSecureStore.platform.PlatformSecureStorage;
import com.OsSecureStore.platform.windows.WindowsSecureStorage;

import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Main API for OsSecureStore
 * Provides methods for securely storing and retrieving data
 */
public class OsSecureStore {

    private static final String DEFAULT_APP_NAME = "OsSecureStoreApp";
    private static String appName = null;
    private static PlatformSecureStorage platformStorage;

    static {
        try {
            platformStorage = SecureStorageFactory.getSecureStorage();
            platformStorage.initialize();
        } catch (SecureStorageException e) {
            System.err.println("Error initializing secure storage: " + e.getMessage());
        }
    }

    /**
     * Sets the application name used for storage
     * @param name Application name
     */
    public static void setApplicationName(String name) throws SecureStorageException {
        //System.out.println("Setting application name to: " + name);
        appName = name;
        platformStorage.setAppPrefix(appName);
    }

    /**
     * Gets the current application name, detecting it if not explicitly set
     * @return The application name
     */
    private static String getApplicationName() throws SecureStorageException {
        // If app name was explicitly set, use it
        if (appName != null) {
            System.out.println("Using explicit application name: " + appName);
            return appName;
        }

        // Otherwise auto-detect
        String detectedName = detectApplicationName();
        appName = detectedName; // Cache the result
        System.out.println("Auto-detected application name: " + appName);
        platformStorage.setAppPrefix(appName);
        return detectedName;
    }

    /**
     * Securely stores a value with the given key
     * @param key Key to associate with the value
     * @param value Value to store
     * @throws SecureStorageException if storage fails
     */
    public static void store(String key, String value) throws SecureStorageException {
        if (platformStorage == null) {
            throw new SecureStorageException("Secure storage not initialized");
        }

        // Ensure app name is set
        if (appName == null) {
            getApplicationName();
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            // Use direct credential storage
            ((WindowsSecureStorage) platformStorage).storeCredential(key, value);
        } else {
            // Legacy implementation for other platforms until they're updated
            throw new SecureStorageException("Platform not supported");
        }
    }

    /**
     * Retrieves a securely stored value
     * @param key Key associated with the value
     * @return The retrieved value, or null if not found
     * @throws SecureStorageException if retrieval fails
     */
    public static String retrieve(String key) throws SecureStorageException {
        if (platformStorage == null) {
            throw new SecureStorageException("Secure storage not initialized");
        }

        // Ensure app name is set
        if (appName == null) {
            getApplicationName();
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            // Use direct credential retrieval
            return ((WindowsSecureStorage) platformStorage).retrieveCredential(key);
        } else {
            // Legacy implementation for other platforms until they're updated
            throw new SecureStorageException("Platform not supported");
        }
    }

    /**
     * Removes a value from secure storage
     * @param key Key to remove
     * @throws SecureStorageException if removal fails
     */
    public static void remove(String key) throws SecureStorageException {
        if (platformStorage == null) {
            throw new SecureStorageException("Secure storage not initialized");
        }

        // Ensure app name is set
        if (appName == null) {
            getApplicationName();
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            // Use direct credential removal
            ((WindowsSecureStorage) platformStorage).removeCredential(key);
        } else {
            // Legacy implementation for other platforms until they're updated
            throw new SecureStorageException("Platform not supported");
        }
    }

    /**
     * Checks if a key exists in secure storage
     * @param key Key to check
     * @return true if the key exists, false otherwise
     * @throws SecureStorageException if the check fails
     */
    public static boolean exists(String key) throws SecureStorageException {
        if (platformStorage == null) {
            throw new SecureStorageException("Secure storage not initialized");
        }

        // Ensure app name is set
        if (appName == null) {
            getApplicationName();
        }

        if (platformStorage instanceof WindowsSecureStorage) {
            // Use direct credential check
            return ((WindowsSecureStorage) platformStorage).credentialExists(key);
        } else {
            // Legacy implementation for other platforms until they're updated
            throw new SecureStorageException("Platform not supported");
        }
    }

    /**
     * Clears all stored values (not supported with Credential Manager)
     * @throws SecureStorageException always thrown as this operation isn't supported
     */
    public static void clear() throws SecureStorageException {
        throw new SecureStorageException("Clear operation not supported with OS credential stores");
    }


    /**
     * Detects the user's application name by analyzing the stack trace or JARs in the classpath.
     * @return The detected application name (e.g., "ProjectX"), or a fallback ID if detection fails.
     */
    private static String detectApplicationName() {
        // 1. First, try to find the user's main JAR (excluding our library)
        String appName = detectFromJarManifest();
        if (appName != null) {
            return appName;
        }

        // 2. Fallback to stack trace analysis (find the first non-library class)
        appName = detectFromStackTrace();
        if (appName != null) {
            return appName;
        }

        // 3. Ultimate fallback: Use a hash of the user's classpath or default
        return generateClasspathHash();
    }

    // Keep the other detection methods as they are...

    /**
     * Checks JAR manifests in the classpath for "Implementation-Title" (user-friendly name).
     */
    private static String detectFromJarManifest() {
        try {
            ClassLoader cl = ClassLoader.getSystemClassLoader();
            if (cl instanceof URLClassLoader) {
                URL[] urls = ((URLClassLoader) cl).getURLs();

                for (URL url : urls) {
                    String path = url.getPath();
                    if (path.endsWith(".jar") && !path.contains("ossecurestore")) {
                        try (JarFile jar = new JarFile(path)) {
                            Manifest manifest = jar.getManifest();
                            if (manifest != null) {
                                String title = manifest.getMainAttributes().getValue("Implementation-Title");
                                if (title != null && !title.isEmpty()) {
                                    return title; // e.g., "ProjectX"
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Analyzes the stack trace to find the first non-library class.
     */
    private static String detectFromStackTrace() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            if (!className.startsWith("com.OsSecureStore") &&
                    !className.startsWith("java.") &&
                    !className.startsWith("sun.")) {
                // Extract the top-level package name (e.g., "com.projectx.Main" → "projectx")
                String[] parts = className.split("\\.");
                return parts.length > 1 ? parts[1] : "app";
            }
        }
        return null;
    }

    /**
     * Generates a short hash from the classpath to ensure uniqueness.
     */
    private static String generateClasspathHash() {
        try {
            String classpath = System.getProperty("java.class.path");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(classpath.getBytes());
            return "app-" + bytesToHex(hash).substring(0, 8); // e.g., "app-a3c8f2b1"
        } catch (Exception e) {
            return DEFAULT_APP_NAME; // Use default app name as ultimate fallback
        }
    }

    /**
     * Helper method to convert byte array to hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}