package com.OsSecureStore.util;

/**
 * Utility class to detect the current platform
 */
public class PlatformDetector {

    public static final String WINDOWS = "windows";
    public static final String MACOS = "macos";
    public static final String LINUX = "linux";
    public static final String UNKNOWN = "unknown";

    /**
     * Gets the current operating system
     * @return The operating system identifier (windows, macos, linux, or unknown)
     */
    public static String getOperatingSystem() {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            return WINDOWS;
        } else if (os.contains("mac")) {
            return MACOS;
        } else if (os.contains("linux") || os.contains("unix")) {
            return LINUX;
        } else {
            return UNKNOWN;
        }
    }

    /**
     * Checks if the current OS is Windows
     * @return true if Windows, false otherwise
     */
    public static boolean isWindows() {
        return getOperatingSystem().equals(WINDOWS);
    }

    /**
     * Checks if the current OS is macOS
     * @return true if macOS, false otherwise
     */
    public static boolean isMacOS() {
        return getOperatingSystem().equals(MACOS);
    }

    /**
     * Checks if the current OS is Linux
     * @return true if Linux, false otherwise
     */
    public static boolean isLinux() {
        return getOperatingSystem().equals(LINUX);
    }
}