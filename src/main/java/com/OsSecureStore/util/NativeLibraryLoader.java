package com.OsSecureStore.util;

import java.io.*;
import java.nio.file.*;

/**
 * Utility class for loading native libraries
 */
public class NativeLibraryLoader {

    private static final String TEMP_DIR_PREFIX = "ossecurestore";

    /**
     * Loads a native library from the resources
     * @param libraryName Name of the library without extension
     * @throws IOException if the library cannot be loaded
     */
    public static void loadLibrary(String libraryName) throws IOException {
        String os = PlatformDetector.getOperatingSystem();
        String arch = System.getProperty("os.arch").toLowerCase();
        String extension = getLibraryExtension(os);


        String resourcePath = String.format("/native/%s-%s/%s%s",
                os, getArchName(arch), libraryName, extension);


        try {
            // Extract the library to a temp file
            Path tempLibrary = extractLibrary(resourcePath);

            // Load the library
            System.load(tempLibrary.toString());
        } catch (IOException e) {
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

    private static Path extractLibrary(String resourcePath) throws IOException {
        // Create temp directory if it doesn't exist
        Path tempDir = Files.createTempDirectory(TEMP_DIR_PREFIX);
        tempDir.toFile().deleteOnExit();

        // Get the filename from the resource path
        String fileName = Paths.get(resourcePath).getFileName().toString();
        Path tempLibrary = tempDir.resolve(fileName);

        // Copy the library from resources to the temp file
        try (InputStream in = NativeLibraryLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IOException("Native library not found: " + resourcePath);
            }

            Files.copy(in, tempLibrary, StandardCopyOption.REPLACE_EXISTING);
        }

        tempLibrary.toFile().deleteOnExit();
        return tempLibrary;
    }
}