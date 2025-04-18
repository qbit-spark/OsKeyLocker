package com.OsKeyLocker.util;

import com.OsKeyLocker.exceptions.KeyLockerException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility class for AES encryption and decryption with initialization vectors
 */
public class EncryptionUtil {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private SecretKeySpec secretKey;

    /**
     * Creates a new EncryptionUtil instance with a provided encryption key
     * @param encryptionKey The key to use for encryption/decryption
     * @throws KeyLockerException if initialization fails
     */
    public EncryptionUtil(String encryptionKey) throws KeyLockerException {
        try {
            // Generate a fixed-length key using the provided encryption key as seed
            byte[] keyBytes = encryptionKey.getBytes(StandardCharsets.UTF_8);
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            keyBytes = sha.digest(keyBytes);
            keyBytes = Arrays.copyOf(keyBytes, 32); // Use only first 256 bits
            secretKey = new SecretKeySpec(keyBytes, "AES");
        } catch (NoSuchAlgorithmException e) {
            throw new KeyLockerException("Failed to initialize encryption", e);
        }
    }

    /**
     * Encrypts a string using AES/GCM
     * @param plainText The string to encrypt
     * @return Base64-encoded encrypted string with embedded IV
     * @throws KeyLockerException if encryption fails
     */
    public String encrypt(String plainText) throws KeyLockerException {
        try {
            // Generate a random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Initialize cipher with key and IV
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            // Encrypt the data
            byte[] encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Combine IV and encrypted data
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedData.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedData);

            // Return as Base64 string
            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            throw new KeyLockerException("Encryption failed", e);
        }
    }

    /**
     * Decrypts a string that was encrypted using the encrypt method
     * @param encryptedText Base64-encoded encrypted string with embedded IV
     * @return The decrypted string
     * @throws KeyLockerException if decryption fails
     */
    public String decrypt(String encryptedText) throws KeyLockerException {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedText);

            // Extract IV and ciphertext
            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            // Decrypt and return as string
            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new KeyLockerException("Decryption failed", e);
        }
    }

    /**
     * Generates a random encryption key
     * @return A Base64-encoded random AES key
     * @throws KeyLockerException if key generation fails
     */
    public static String generateEncryptionKey() throws KeyLockerException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new KeyLockerException("Failed to generate encryption key", e);
        }
    }
}