package com.OsKeyLocker;


import com.OsKeyLocker.exceptions.PlatformNotSupportedException;
import com.OsKeyLocker.platform.PlatformKeyLockerStorage;
import com.OsKeyLocker.platform.windows.WindowsSecureStorage;
import com.OsKeyLocker.util.PlatformDetector;

/**
 * Factory for creating platform-specific secure storage implementations
 */
public class KeyLockerStoreFactory {

    /**
     * Creates a secure storage implementation for the current platform
     * @return Platform-specific secure storage implementation
     * @throws PlatformNotSupportedException if the current platform is not supported
     */
    public static PlatformKeyLockerStorage getSecureStorage() throws PlatformNotSupportedException {
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