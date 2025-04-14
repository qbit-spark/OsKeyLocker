package com.OsSecureStore.platform.windows;

import com.OsSecureStore.exceptions.SecureStorageException;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * Provides access to Windows Credential Manager API
 */
public class WindowsCredentialManager {

    private Advapi32 advapi32;
    private Kernel32 kernel32;
    private String appPrefix;

    // Windows Credential type
    private static final int CRED_TYPE_GENERIC = 1;
    // Credential persistence
    private static final int CRED_PERSIST_LOCAL_MACHINE = 2;

    /**
     * Interface for accessing Windows Credential Manager functions
     */
    public interface Advapi32 extends StdCallLibrary {
        boolean CredReadA(String targetName, int type, int flags, PointerByReference credentialPtr);
        boolean CredWriteA(CREDENTIAL credential, int flags);
        boolean CredDeleteA(String targetName, int type, int flags);
        boolean CredFree(Pointer credential);
    }

    /**
     * Interface for Windows kernel functions
     */
    public interface Kernel32 extends StdCallLibrary {
        int GetLastError();
    }

    /**
     * Structure representing a Windows credential
     */
    public static class CREDENTIAL extends com.sun.jna.Structure {
        public int Flags;
        public int Type;
        public String TargetName;
        public String Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public Pointer CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public Pointer Attributes;
        public String TargetAlias;
        public String UserName;

        protected java.util.List<String> getFieldOrder() {
            return Arrays.asList(
                    "Flags", "Type", "TargetName", "Comment", "LastWritten",
                    "CredentialBlobSize", "CredentialBlob", "Persist",
                    "AttributeCount", "Attributes", "TargetAlias", "UserName"
            );
        }

        public CREDENTIAL() {}

        public CREDENTIAL(Pointer p) {
            super(p);
            read();
        }
    }

    /**
     * Creates a new WindowsCredentialManager instance
     */
    public WindowsCredentialManager() {
        this.appPrefix = "OsSecureStore:";
    }

    /**
     * Initializes the Windows Credential Manager
     */
    public void initialize() {
        this.advapi32 = Native.load("Advapi32", Advapi32.class);
        this.kernel32 = Native.load("Kernel32", Kernel32.class);
    }

    /**
     * Sets a custom application prefix for credential names
     * @param prefix Custom prefix
     */
    public void setAppPrefix(String prefix) {
        System.out.println("WindowsCredentialManager - Setting prefix to: " + prefix);
        this.appPrefix = prefix + ":";
    }

    /**
     * Builds the full credential name with prefix
     * @param key Base credential key
     * @return Full credential name
     */
    private String buildCredentialName(String key) {
        String fullName = appPrefix + key;
        System.out.println("Built credential name: " + fullName);
        return fullName;
    }

    /**
     * Adds or updates a credential in Windows Credential Manager
     * @param key Credential key
     * @param value Credential value
     * @throws SecureStorageException if the operation fails
     */
    public void addCredential(String key, String value) throws SecureStorageException {
        String credName = buildCredentialName(key);

        CREDENTIAL credential = new CREDENTIAL();
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = credName;
        credential.Comment = "Stored by OsSecureStore";
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        credential.UserName = System.getProperty("user.name");

        byte[] passwordBytes = value.getBytes(Charset.forName("UTF-16LE"));

        try (Memory passwordMemory = new Memory(passwordBytes.length)) {
            passwordMemory.write(0, passwordBytes, 0, passwordBytes.length);
            credential.CredentialBlob = passwordMemory;
            credential.CredentialBlobSize = passwordBytes.length;

            boolean success = advapi32.CredWriteA(credential, 0);

            if (!success) {
                int errorCode = kernel32.GetLastError();
                throw new SecureStorageException("Failed to write credential, error code: " + errorCode);
            }
        }
    }

    /**
     * Retrieves a credential from Windows Credential Manager
     * @param key Credential key
     * @return Credential value
     * @throws SecureStorageException if the credential cannot be found or retrieved
     */
    public String getCredential(String key) throws SecureStorageException {
        String credName = buildCredentialName(key);
        PointerByReference credentialPtr = new PointerByReference();

        boolean success = advapi32.CredReadA(credName, CRED_TYPE_GENERIC, 0, credentialPtr);

        if (!success) {
            int errorCode = kernel32.GetLastError();
            throw new SecureStorageException("Credential not found, error code: " + errorCode);
        }

        CREDENTIAL credential = new CREDENTIAL(credentialPtr.getValue());

        try {
            byte[] passwordBytes = credential.CredentialBlob.getByteArray(0, credential.CredentialBlobSize);
            return new String(passwordBytes, Charset.forName("UTF-16LE"));
        } finally {
            advapi32.CredFree(credentialPtr.getValue());
        }
    }

    /**
     * Deletes a credential from Windows Credential Manager
     * @param key Credential key
     * @throws SecureStorageException if the credential cannot be deleted
     */
    public void deleteCredential(String key) throws SecureStorageException {
        String credName = buildCredentialName(key);

        boolean success = advapi32.CredDeleteA(credName, CRED_TYPE_GENERIC, 0);

        if (!success) {
            int errorCode = kernel32.GetLastError();
            throw new SecureStorageException("Failed to delete credential, error code: " + errorCode);
        }
    }

    /**
     * Checks if a credential exists in Windows Credential Manager
     * @param key Credential key
     * @return true if the credential exists, false otherwise
     */
    public boolean credentialExists(String key) {
        String credName = buildCredentialName(key);
        PointerByReference credentialPtr = new PointerByReference();

        boolean success = advapi32.CredReadA(credName, CRED_TYPE_GENERIC, 0, credentialPtr);

        if (success) {
            advapi32.CredFree(credentialPtr.getValue());
            return true;
        }

        return false;
    }
}