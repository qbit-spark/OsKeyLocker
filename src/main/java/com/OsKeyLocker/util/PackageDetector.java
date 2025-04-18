package com.OsKeyLocker.util;

import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
/**
 * Utility for detecting the package name of the calling application
 */
public class PackageDetector {

    private static final String DEFAULT_PACKAGE = "default";

    /**
     * Detects the package name of the calling application by analyzing the stack trace
     * @return The detected package name
     */
    public static String detectCallingPackage() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

        for (StackTraceElement element : stackTrace) {
            String className = element.getClassName();
            if (!className.startsWith("com.OsKeyLocker") &&
                    !className.startsWith("java.") &&
                    !className.startsWith("sun.") &&
                    !className.startsWith("jdk.")) {

                // Extract the package name
                int lastDot = className.lastIndexOf('.');
                if (lastDot > 0) {
                    return className.substring(0, lastDot);
                } else {
                    return DEFAULT_PACKAGE;
                }
            }
        }


        // If no suitable package was found, use a hash-based unique identifier
        return "app-" + getSystemIdentifier();
    }

    /**
     * Creates a unique identifier based on system properties as a fallback
     * @return A hash-based system identifier
     */
    private static String getSystemIdentifier() {
        try {
            String systemInfo = System.getProperty("user.name") +
                    System.getProperty("user.home") +
                    System.getProperty("os.name");

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(systemInfo.getBytes());

            return bytesToHex(hash).substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            return DEFAULT_PACKAGE;
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