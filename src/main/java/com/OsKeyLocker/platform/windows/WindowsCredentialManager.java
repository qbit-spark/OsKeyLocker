package com.OsKeyLocker.platform.windows;


import com.OsKeyLocker.exceptions.KeyLockerException;
import com.OsKeyLocker.util.EncryptionUtil;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.rmi.server.LogStream.log;

/**
 * Provides access to Windows Credential Manager API with chunking support
 */
@Slf4j
public class WindowsCredentialManager {

    private Advapi32 advapi32;
    private Kernel32 kernel32;
    private String appPrefix;
    private EncryptionUtil encryptionUtil;

    // Maximum size for credential blob (in characters)
    private static final int MAX_CREDENTIAL_SIZE = 1024 ;
    private static final String CHUNK_IDENTIFIER = "CHUNK_";
    private static final String METADATA_KEY = "metadata";

    // Windows Credential type
    private static final int CRED_TYPE_GENERIC = 1;
    // Credential persistence
    private static final int CRED_PERSIST_LOCAL_MACHINE = 2;

    // Interface definitions for Windows APIs
    public interface Advapi32 extends StdCallLibrary {
        boolean CredReadA(String targetName, int type, int flags, PointerByReference credentialPtr);

        boolean CredWriteA(CREDENTIAL credential, int flags);

        boolean CredDeleteA(String targetName, int type, int flags);

        boolean CredFree(Pointer credential);
    }

    public interface Kernel32 extends StdCallLibrary {
        int GetLastError();
    }

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

        public CREDENTIAL() {
        }

        public CREDENTIAL(Pointer p) {
            super(p);
            read();
        }
    }

    /**
     * Creates a new WindowsCredentialManager instance
     */
    public WindowsCredentialManager() {
        this.appPrefix = "OsKeyLocker";
    }

    /**
     * Initializes the Windows Credential Manager with encryption key
     *
     * @param encryptionKey The encryption key to use (may be null for default)
     * @throws KeyLockerException if initialization fails
     */
    public void initialize(String encryptionKey) throws KeyLockerException {
        this.advapi32 = Native.load("Advapi32", Advapi32.class);
        this.kernel32 = Native.load("Kernel32", Kernel32.class);

        if (encryptionKey != null) {
            this.encryptionUtil = new EncryptionUtil(encryptionKey);
        }
    }

    /**
     * Sets the encryption key to use
     *
     * @param encryptionKey The encryption key
     * @throws KeyLockerException if setting the key fails
     */
    public void setEncryptionKey(String encryptionKey) throws KeyLockerException {
        this.encryptionUtil = new EncryptionUtil(encryptionKey);
    }

    /**
     * Sets the application prefix for credential names based on package name
     *
     * @param packageName Application package name
     * @param packageName Application package name
     * @throws KeyLockerException if setting the prefix fails
     *                                Sets the application prefix for credential names based on package name
     */
    public void setAppPrefix(String packageName) {
        this.appPrefix = "OsKeyLocker." + packageName;
    }

    /**
     * Builds the full credential name with prefix
     *
     * @param key Base credential key
     * @return Full credential name
     */
    private String buildCredentialName(String key) {
        return appPrefix + "." + key;
    }

    /**
     * Builds a chunk credential name
     *
     * @param key        Base credential key
     * @param chunkIndex The chunk index
     * @return Chunk credential name
     */
    private String buildChunkName(String key, int chunkIndex) {
        return buildCredentialName(key) + "." + CHUNK_IDENTIFIER + chunkIndex;
    }

    /**
     * Adds or updates a credential with JSON value in Windows Credential Manager
     *
     * @param key       Credential key
     * @param jsonValue JSON object value to store
     * @throws KeyLockerException if the operation fails
     */
    public void addCredential(String key, JSONObject jsonValue) throws KeyLockerException {
        String encryptedValue = encryptionUtil.encrypt(jsonValue.toString());

        //Todo: lets print encrypted value
        //System.out.println("🚨Encrypted value: " + encryptedValue);
        //System.out.println("🚨 Encrypted value size: " + encryptedValue.length() + " bytes for key: " + key);


        // Check if chunking is needed
        if (encryptedValue.length() <= MAX_CREDENTIAL_SIZE) {

            // Store as a single credential
            addRawCredential(buildCredentialName(key), encryptedValue);

            System.out.println("------ Using single credential (no chunking needed) -------");

            // Add metadata (no chunks)
            JSONObject metadata = new JSONObject();
            metadata.put("chunks", 0);
            metadata.put("totalLength", encryptedValue.length());
            addRawCredential(buildCredentialName(key + "." + METADATA_KEY), encryptionUtil.encrypt(metadata.toString()));
        } else {
            // Need to chunk the credential
            List<String> chunks = chunkString(encryptedValue, MAX_CREDENTIAL_SIZE);

            System.out.println("----- Large value detected! Splitting into " + chunks.size() + " chunks -------");

            // Store metadata first
            JSONObject metadata = new JSONObject();
            metadata.put("chunks", chunks.size());
            metadata.put("totalLength", encryptedValue.length());
            addRawCredential(buildCredentialName(key + "." + METADATA_KEY), encryptionUtil.encrypt(metadata.toString()));

            // Store each chunk
            for (int i = 0; i < chunks.size(); i++) {
                addRawCredential(buildChunkName(key, i), chunks.get(i));
            }
        }
    }

    /**
     * Adds a raw credential string to Windows Credential Manager
     *
     * @param credName The full credential name
     * @param value    The string value to store
     * @throws KeyLockerException if the operation fails
     */
    private void addRawCredential(String credName, String value) throws KeyLockerException {

        //Todo: lets print these credName and value
//        System.out.println("🚨??Credential Name: " + credName);
//        System.out.println("🚨??Credential Value: " + value);

        CREDENTIAL credential = new CREDENTIAL();
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = credName;
        credential.Comment = "Stored by OsKeyLocker";
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
                throw new KeyLockerException("Failed to write credential, error code: " + errorCode);
            }
        }
    }

    /**
     * Retrieves a JSON credential from Windows Credential Manager
     *
     * @param key Credential key
     * @return JSON Object value
     * @throws KeyLockerException if the credential cannot be found or retrieved
     */
    public JSONObject getCredential(String key) throws KeyLockerException {
        // First check metadata to see if chunking is used
        String metadataKey = buildCredentialName(key + "." + METADATA_KEY);
        String encryptedMetadata = getRawCredential(metadataKey);

        if (encryptedMetadata == null) {
            throw new KeyLockerException("Credential metadata not found for key: " + key);
        }

        String decryptedMetadata = encryptionUtil.decrypt(encryptedMetadata);
        JSONObject metadata = new JSONObject(decryptedMetadata);

        int chunks = metadata.getInt("chunks");

        if (chunks == 0) {
            // Not chunked, retrieve the entire credential
            String encryptedValue = getRawCredential(buildCredentialName(key));
            if (encryptedValue == null) {
                throw new KeyLockerException("Credential not found for key: " + key);
            }

            String decryptedValue = encryptionUtil.decrypt(encryptedValue);
            return new JSONObject(decryptedValue);
        } else {
            // Chunked credential, retrieve and combine chunks
            StringBuilder combinedValue = new StringBuilder();

            for (int i = 0; i < chunks; i++) {
                String chunkValue = getRawCredential(buildChunkName(key, i));
                if (chunkValue == null) {
                    throw new KeyLockerException("Credential chunk " + i + " not found for key: " + key);
                }
                combinedValue.append(chunkValue);
            }

            String decryptedValue = encryptionUtil.decrypt(combinedValue.toString());
            return new JSONObject(decryptedValue);
        }
    }

    /**
     * Retrieves a raw credential string from Windows Credential Manager
     *
     * @param credName The full credential name
     * @return The credential value as a string, or null if not found
     * @throws KeyLockerException if retrieval fails for technical reasons
     */
    private String getRawCredential(String credName) throws KeyLockerException {
        PointerByReference credentialPtr = new PointerByReference();

        boolean success = advapi32.CredReadA(credName, CRED_TYPE_GENERIC, 0, credentialPtr);

        if (!success) {
            int errorCode = kernel32.GetLastError();
            if (errorCode == 1168) { // ERROR_NOT_FOUND
                return null;
            }
            throw new KeyLockerException("Failed to read credential, error code: " + errorCode);
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
     * Deletes a credential and all its chunks from Windows Credential Manager
     *
     * @param key Credential key
     * @throws KeyLockerException if the credential cannot be deleted
     */
    public void deleteCredential(String key) throws KeyLockerException {
       // System.out.println("🔄 Attempting to delete credential: " + key);

        // First check metadata to see if chunking is used
        String metadataKey = buildCredentialName(key + "." + METADATA_KEY);
        String encryptedMetadata;

        try {
            encryptedMetadata = getRawCredential(metadataKey);
           // System.out.println("📋 Found metadata for: " + key);

            if (encryptedMetadata != null) {
                try {
                    String decryptedMetadata = encryptionUtil.decrypt(encryptedMetadata);
                    JSONObject metadata = new JSONObject(decryptedMetadata);

                    int chunks = metadata.getInt("chunks");

                    //System.out.println("📦 Credential has " + chunks + " chunks to delete");

                    if (chunks > 0) {
                        // Delete all chunks
                        for (int i = 0; i < chunks; i++) {
                            //System.out.println("🗑️ Deleting chunk " + (i+1) + " of " + chunks);
                            deleteRawCredential(buildChunkName(key, i));
                        }
                    }
                } catch (Exception e) {
                    //System.out.println("⚠️ Failed to decrypt metadata: " + e.getMessage());
                    // Continue with deletion even if decryption fails
                    // Try to delete potential chunks using a reasonable upper limit
                   // System.out.println("🔄 Falling back to brute force chunk deletion");
                    for (int i = 0; i < 20; i++) { // Assume no more than 20 chunks
                        try {
                            deleteRawCredential(buildChunkName(key, i));
                        } catch (Exception ex) {
                            // Ignore errors for chunks that don't exist
                        }
                    }
                }
            }
        } catch (Exception e) {
            //System.out.println("⚠️ Error accessing metadata: " + e.getMessage());
            // Continue to delete main credential even if metadata access fails
        }

        // Always attempt to delete main credential and metadata
        //System.out.println("🗑️ Deleting main credential");
        deleteRawCredential(buildCredentialName(key));

        //System.out.println("🗑️ Deleting metadata");
        deleteRawCredential(metadataKey);

       // System.out.println("✅ Credential deletion completed");
    }


    /**
     * Deletes a raw credential from Windows Credential Manager
     *
     * @param credName The full credential name
     * @throws KeyLockerException if deletion fails
     */
    private void deleteRawCredential(String credName) throws KeyLockerException {
        boolean success = advapi32.CredDeleteA(credName, CRED_TYPE_GENERIC, 0);

        if (!success) {
            int errorCode = kernel32.GetLastError();
            if (errorCode != 1168) { // Ignore ERROR_NOT_FOUND
                throw new KeyLockerException("Failed to delete credential, error code: " + errorCode);
            }
        }
    }

    /**
     * Checks if a credential exists in Windows Credential Manager
     *
     * @param key Credential key
     * @return true if the credential exists, false otherwise
     */
    public boolean credentialExists(String key) {
        try {
            // Check for metadata existence
            String metadataKey = buildCredentialName(key + "." + METADATA_KEY);
            String encryptedMetadata = getRawCredential(metadataKey);

            return encryptedMetadata != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Updates a specific key in a JSON object credential
     *
     * @param key       Main credential key
     * @param jsonKey   The JSON field key to update
     * @param jsonValue The new value for the JSON field
     * @throws KeyLockerException if the operation fails
     */
    public void updateCredentialField(String key, String jsonKey, Object jsonValue) throws KeyLockerException {
        JSONObject existingData;

        try {
            existingData = getCredential(key);
        } catch (KeyLockerException e) {
            // If credential doesn't exist, create a new one
            existingData = new JSONObject();
        }

        // Update the field
        existingData.put(jsonKey, jsonValue);

        // Store the updated credential
        addCredential(key, existingData);
    }

    /**
     * Helper method to split a string into chunks of maximum size
     *
     * @param input     The string to chunk
     * @param chunkSize Maximum chunk size
     * @return List of string chunks
     */
    private List<String> chunkString(String input, int chunkSize) {
        List<String> chunks = new ArrayList<>();
        int length = input.length();

        for (int i = 0; i < length; i += chunkSize) {
            chunks.add(input.substring(i, Math.min(length, i + chunkSize)));
        }

        return chunks;
    }
}
