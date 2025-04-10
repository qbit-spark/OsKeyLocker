package com.OsSecureStore.platform.windows;

import com.OsSecureStore.util.NativeLibraryLoader;

import java.io.IOException;
import java.util.Base64;

/**
 * JNI wrapper for Windows DPAPI
 */
public class WindowsDPAPI {

    static {
        try {
           System.loadLibrary("src/main/resources/native/windows-x86_64/libWindowsDPAPI");
        } catch (UnsatisfiedLinkError e) {
            // Will be handled when methods are called
            throw new RuntimeException("Failed to load Windows DPAPI library", e);
        }
    }

    /**
     * Protects (encrypts) data using Windows DPAPI
     * @param data Data to encrypt
     * @return Encrypted data
     */
    public native byte[] protect(byte[] data);

    /**
     * Unprotects (decrypts) data using Windows DPAPI
     * @param encryptedData Data to decrypt
     * @return Decrypted data
     */
    public native byte[] unprotect(byte[] encryptedData);

    /**
     * Encrypts a string using Windows DPAPI and encodes it as Base64
     * @param data String to encrypt
     * @return Base64-encoded encrypted string
     */
    public String protectString(String data) {
        byte[] protectedData = protect(data.getBytes());
        return Base64.getEncoder().encodeToString(protectedData);
    }

    /**
     * Decrypts a Base64-encoded encrypted string using Windows DPAPI
     * @param encryptedData Base64-encoded encrypted string
     * @return Decrypted string
     */
    public String unprotectString(String encryptedData) {
        byte[] protectedData = Base64.getDecoder().decode(encryptedData);
        byte[] unprotectedData = unprotect(protectedData);
        return new String(unprotectedData);
    }
}