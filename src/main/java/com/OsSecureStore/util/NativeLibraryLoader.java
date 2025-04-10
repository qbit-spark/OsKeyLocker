package com.OsSecureStore.util;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Utility class for loading native libraries from inside the JAR
 */
public class NativeLibraryLoader {

    private static final String TEMP_DIR_PREFIX = "ossecurestore";
    private static final String LIBRARY_DIR = "native";

    /**
     * Loads a native library from the resources
     * @param libraryName Name of the library without extension
     * @throws IOException if the library cannot be loaded
     */
    public static void loadLibrary(String libraryName) throws IOException {
        String os = PlatformDetector.getOperatingSystem();
        String arch = System.getProperty("os.arch").toLowerCase();
        String extension = getLibraryExtension(os);

        // Form the resource path
        String resourcePath = "/" + LIBRARY_DIR + "/" + os + "-" + getArchName(arch) + "/" + libraryName + extension;

        // Extract and load the library
        try {
            // Get the library as a resource stream
            InputStream libraryStream = NativeLibraryLoader.class.getResourceAsStream(resourcePath);
            if (libraryStream == null) {
                throw new IOException("Native library not found in JAR: " + resourcePath);
            }

            // Read the library bytes
            byte[] libraryBytes = libraryStream.readAllBytes();
            libraryStream.close();

            // Create a unique filename based on the library content hash
            String uniqueLibName = createUniqueLibraryName(libraryName, libraryBytes, extension);

            // Get the temporary directory
            Path tempDir = getTempDirectory();
            Path libraryPath = tempDir.resolve(uniqueLibName);

            // Extract library only if it doesn't exist yet
            if (!Files.exists(libraryPath)) {
                Files.write(libraryPath, libraryBytes);
                // Ensure the file will be deleted when the JVM exits
                libraryPath.toFile().deleteOnExit();
            }

            // Load the library
            System.load(libraryPath.toString());

        } catch (Exception e) {
            throw new IOException("Failed to load native library: " + libraryName, e);
        }
    }

    private static String getLibraryExtension(String os) {
        if (PlatformDetector.WINDOWS.equals(os)) {
            return ".dll";
        } else if (PlatformDetector.MACOS.equals(os)) {
            return ".dylib";
        } else {
            return ".so";
        }
    }

    private static String getArchName(String arch) {
        if (arch.contains("64")) {
            return "x86_64";
        } else {
            return "x86";
        }
    }

    private static Path getTempDirectory() throws IOException {
        // Create a persistent temp directory for the library
        String tempDirPath = System.getProperty("java.io.tmpdir");
        Path tempDir = Paths.get(tempDirPath, TEMP_DIR_PREFIX);

        if (!Files.exists(tempDir)) {
            Files.createDirectories(tempDir);
        }

        return tempDir;
    }

    private static String createUniqueLibraryName(String libraryName, byte[] libraryBytes, String extension) {
        // Create a hash of the library content to ensure uniqueness
        String hash = "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(libraryBytes);
            hash = "-" + HexFormat.of().formatHex(digest).substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            // If hashing fails, use a timestamp instead
            hash = "-" + System.currentTimeMillis();
        }

        return libraryName + hash + extension;
    }
}