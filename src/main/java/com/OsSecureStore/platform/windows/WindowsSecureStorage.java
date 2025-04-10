package com.OsSecureStore.platform.windows;

import com.OsSecureStore.exceptions.SecureStorageException;
import com.OsSecureStore.platform.PlatformSecureStorage;
import com.OsSecureStore.util.NativeLibraryLoader;
import com.OsSecureStore.util.PlatformDetector;

import java.io.IOException;

/**
 * Windows implementation of secure storage using DPAPI
 */
public class WindowsSecureStorage implements PlatformSecureStorage {

    private WindowsDPAPI dpapi;
    private boolean initialized = false;

    /**
     * Creates a new WindowsSecureStorage instance
     */
    public WindowsSecureStorage() {
        this.dpapi = new WindowsDPAPI();
    }

    @Override
    public byte[] encrypt(byte[] data) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        try {
            return dpapi.protect(data);
        } catch (UnsatisfiedLinkError e) {
            throw new SecureStorageException("Failed to encrypt data: Native library not loaded", e);
        } catch (Exception e) {
            throw new SecureStorageException("Failed to encrypt data", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws SecureStorageException {
        if (!initialized) {
            initialize();
        }

        try {
            return dpapi.unprotect(encryptedData);
        } catch (UnsatisfiedLinkError e) {
            throw new SecureStorageException("Failed to decrypt data: Native library not loaded", e);
        } catch (Exception e) {
            throw new SecureStorageException("Failed to decrypt data", e);
        }
    }

    @Override
    public void initialize() throws SecureStorageException {
        if (!isSupported()) {
            throw new SecureStorageException("Windows platform is not supported on this system");
        }

        try {
            NativeLibraryLoader.loadLibrary("libWindowsDPAPI");
            initialized = true;
        } catch (IOException e) {
            throw new SecureStorageException("Failed to initialize Windows secure storage", e);
        }
    }

    @Override
    public boolean isSupported() {
        return PlatformDetector.isWindows();
    }
}