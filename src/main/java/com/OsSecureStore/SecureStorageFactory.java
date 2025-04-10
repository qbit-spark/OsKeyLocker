package com.OsSecureStore;

import com.OsSecureStore.exceptions.PlatformNotSupportedException;
import com.OsSecureStore.platform.PlatformSecureStorage;
import com.OsSecureStore.platform.windows.WindowsSecureStorage;
import com.OsSecureStore.util.PlatformDetector;

/**
 * Factory for creating platform-specific secure storage implementations
 */
public class SecureStorageFactory {

    /**
     * Creates a secure storage implementation for the current platform
     * @return Platform-specific secure storage implementation
     * @throws PlatformNotSupportedException if the current platform is not supported
     */
    public static PlatformSecureStorage getSecureStorage() throws PlatformNotSupportedException {
        String os = PlatformDetector.getOperatingSystem();

        switch (os) {
            case PlatformDetector.WINDOWS:
                return new WindowsSecureStorage();
            case PlatformDetector.MACOS:
                throw new PlatformNotSupportedException("macOS support not yet implemented");
            case PlatformDetector.LINUX:
                throw new PlatformNotSupportedException("Linux support not yet implemented");
            default:
                throw new PlatformNotSupportedException("Unsupported platform: " + os);
        }
    }
}