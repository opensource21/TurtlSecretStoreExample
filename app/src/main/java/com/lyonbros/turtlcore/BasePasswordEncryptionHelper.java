package com.lyonbros.turtlcore;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

/**
 * Helperclass which handles the password base encryption. It has a method which delivers the password.
 */
abstract class BasePasswordEncryptionHelper {

    private static final String PW_GEN_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String CIPHER_MODE_PW = "AES/CBC/PKCS5Padding";

    // Methods
    final byte[] encrypt(byte[] clear) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        final SecureRandom random = new SecureRandom();
        final byte[] salt = new byte[16];
        random.nextBytes(salt);

        SecretKey key = createSecretKey(salt);

        final byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        final IvParameterSpec iv = new IvParameterSpec(ivBytes);

        final Cipher c = Cipher.getInstance(CIPHER_MODE_PW);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        final byte[] encValue = c.doFinal(clear);

        final byte[] finalCiphertext = new byte[encValue.length+2*16];
        System.arraycopy(ivBytes, 0, finalCiphertext, 0, 16);
        System.arraycopy(salt, 0, finalCiphertext, 16, 16);
        System.arraycopy(encValue, 0, finalCiphertext, 32, encValue.length);

        return finalCiphertext;
    }

    final byte[] decrypt(byte[] encrypted) throws BadPaddingException, IllegalBlockSizeException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        final byte[] salt = Arrays.copyOfRange(encrypted, 16, 32);
        SecretKey key = createSecretKey(salt);

        final byte[] ivByte = Arrays.copyOfRange(encrypted, 0, 16);
        final byte[] encValue = Arrays.copyOfRange(encrypted, 32, encrypted.length);

        Cipher c = Cipher.getInstance(CIPHER_MODE_PW);
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivByte));
        return c.doFinal(encValue);
    }

    private SecretKey createSecretKey(byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeySpec spec = new PBEKeySpec(buildPassword().toCharArray(), salt, 20, 128); // AES-128
        final SecretKeyFactory f = SecretKeyFactory.getInstance(PW_GEN_ALGORITHM);
        return f.generateSecret(spec);
    }


    private String buildPassword() {
        // TODO build dialog to get password.
        String password = "";
        // FIX-Passwords are unsecure, but it's more like a fix salt. The user can prefix a good password.
        return password + "TURTLlkajshfddsahfkdsajhf";
    }

    /**
     * Returns the password a user asked for.
     */
    abstract String getPassword();

}
