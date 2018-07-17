package com.lyonbros.turtlcore;

import android.annotation.SuppressLint;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

/**
 * Class which store the turtl-key for stay logged in. This class tries to avoid to throw any
 * exception, because it should be part of a cordova app, where it becomes difficult,
 * to handle the exception appropriate.<br>
 * How safe is the store? The store is as safe as the keystore of android or your additional password.
 * <p>
 * Quote: The Android Keystore system lets you store cryptographic keys in a container to make it
 * more difficult to extract from the device.
 * Once keys are in the keystore, they can be used for cryptographic operations with the key material
 * remaining non-exportable.
 * Moreover, it offers facilities to restrict when and how keys can be used,
 * such as requiring user authentication for key use or restricting keys to be used only in certain
 * cryptographic modes.
 */
public class SecurityStore {

    private static final String LOG_TAG_NAME = "SecurityStore";
    private static final String CIPHER_MODE = "AES/GCM/NoPadding";

    // DONT CHANGE THE VALUE!
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TURTL_KEYSTORE_KEY = "TurtlLoginSecret";
    private static final String TURTL_CRYPTED_KEY = "TURTL_CRYPTED_KEY";
    private static final String TURTL_CRYPTED_IV = "TURTL_CRYPTED_IV";

    private static final String EXTRA_PASSWD = "EXTRA_PASSWD";
    private static final String PW_GEN_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String CIPHER_MODE_PW = "AES/CBC/PKCS5Padding";

    private final String basePasswd;

    // Exsits PIN, Pattern or Fingerprint or something else.
    private final boolean deviceIsProtected;

    private final SharedPreferences preferences;
    private final Context context;

    /**
     * Initialize this object.
     * @param context the context of the android app. Can be get at Cordova-Plugin via <br>
     *                <code>this.cordova.getActivity().getApplicationContext();</code> otherwise
     *                each Activity is a valid context.
     */
    @SuppressLint("HardwareIds")
    public SecurityStore(Context context) {
        this.context = context;
        final KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE); //api 23+
        deviceIsProtected = keyguardManager.isDeviceSecure();
        this.preferences= PreferenceManager.getDefaultSharedPreferences(context);
        // FIX-Passwords are unsecure, but it's more like a fix salt. The user can prefix a good password.
        basePasswd = "TURTLlkajshfddsahfkdsajhf" ;


    }

    public boolean storeKey(byte[] unencryptedKey, SecurityMode securityMode) {
        try {
            final SecurityMode usedSecurityMode;
            if (SecurityMode.AUTHENTICATION.equals(securityMode) && !deviceIsProtected) {
                final String warningText = "Downgrade security mode to none, " +
                        "because there is no screenprotection set!" +
                        "Secure lock screen isn't set up.\n" +
                        "Go to 'Settings -> Security -> Screen lock' to set up a lock screen";
                Toast.makeText(context, warningText,
                        Toast.LENGTH_LONG).show();
                Log.w(LOG_TAG_NAME, warningText);
                usedSecurityMode = SecurityMode.NONE;
            } else {
                usedSecurityMode = securityMode;
            }
            final Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, createSecretKey(usedSecurityMode));
            final byte[] iv = cipher.getIV();
            final byte[] crypteKey = cipher.doFinal(unencryptedKey);
            final SharedPreferences.Editor editor = preferences.edit();
            final boolean extraPassword = SecurityMode.PASSWORD.equals(usedSecurityMode);
            editor.putBoolean(EXTRA_PASSWD, extraPassword);
            if (extraPassword) {
                editor.putString(TURTL_CRYPTED_KEY, Base64.encodeToString(encrypt(crypteKey), Base64.DEFAULT));
            } else {
                editor.putString(TURTL_CRYPTED_KEY, Base64.encodeToString(crypteKey, Base64.DEFAULT));
            }
            editor.putString(TURTL_CRYPTED_IV, Base64.encodeToString(iv, Base64.DEFAULT));
            editor.apply();
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException | NoSuchProviderException |InvalidKeySpecException e) {
            Log.e(LOG_TAG_NAME,"Wrong encryption parameter", e);
        } catch (InvalidAlgorithmParameterException e) {
            if (SecurityMode.AUTHENTICATION.equals(securityMode) && !deviceIsProtected) {
                Log.e(LOG_TAG_NAME, "The device must be proteced by pin or pattern or fingerprint.", e);
            } else {
                Log.e(LOG_TAG_NAME, "Wrong encryption parameter", e);
            }
        }
        preferences.edit().clear().apply();
        return false;
    }

    public boolean storeKey(byte[] unencryptedKey) {
        return storeKey(unencryptedKey, SecurityMode.NONE);
    }

    public boolean storeKey(byte[] unencryptedKey, String securityMode) {
        return storeKey(unencryptedKey, SecurityMode.valueOf(securityMode));
    }


    /**
     * Loads a saved key or <code>null</code> if no key is found.
     * @return the saved key or <code>null</code> if no key is found.
     */
    public byte[] loadKey() {
        final SecretKey secretKey = getSecretKey();
        if (preferences.contains(TURTL_CRYPTED_KEY) && secretKey != null) {
            final byte[] storedKey = Base64.decode(preferences.getString(TURTL_CRYPTED_KEY, null), Base64.DEFAULT);
            final byte[] encryptionIv = Base64.decode(preferences.getString(TURTL_CRYPTED_IV, null), Base64.DEFAULT);
            final boolean passwd = preferences.getBoolean(EXTRA_PASSWD, false);
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(CIPHER_MODE);
                final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
                final byte[] clearKey = passwd ? decrypt(storedKey) : storedKey;
                return cipher.doFinal(clearKey);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                    InvalidAlgorithmParameterException | InvalidKeyException |
                    IllegalBlockSizeException | BadPaddingException|InvalidKeySpecException e) {
                Log.e(LOG_TAG_NAME,"Wrong decryption parameter", e);
            }
        }
        return null;
    }

    @NonNull
    private SecretKey createSecretKey(SecurityMode securityMode) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {

        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        keyGenerator.init(new KeyGenParameterSpec.Builder(TURTL_KEYSTORE_KEY,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(SecurityMode.AUTHENTICATION.equals(securityMode))
                .build());
        return keyGenerator.generateKey();
    }

    private SecretKey getSecretKey()  {
        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(TURTL_KEYSTORE_KEY, null)).getSecretKey();
        } catch (KeyStoreException e) {
            Log.e(LOG_TAG_NAME,"No keystore-provider is founded or can't load key from keystore.", e);
        } catch (CertificateException | IOException e) {
            Log.e(LOG_TAG_NAME,"Can't load keystore.", e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(LOG_TAG_NAME,"Can't load keystore or can't load key from keystore.", e);
        } catch (UnrecoverableEntryException e) {
            Log.e(LOG_TAG_NAME,"Can't load key from keystore.", e);
        }
        return null;
    }

    // Methods
    private byte[] encrypt(byte[] clear) throws NoSuchPaddingException, NoSuchAlgorithmException,
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

    private byte[] decrypt(byte[] encrypted) throws BadPaddingException, IllegalBlockSizeException,
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
        final KeySpec spec = new PBEKeySpec(getPassword().toCharArray(), salt, 20, 128); // AES-128
        final SecretKeyFactory f = SecretKeyFactory.getInstance(PW_GEN_ALGORITHM);
        return f.generateSecret(spec);
    }


    private String getPassword() {
        // TODO build dialog to get password.
        String password = "";
        return password + basePasswd;
    }

    public enum SecurityMode {
        NONE,
        /**
         * User authentication authorizes the use of keys for a duration of time.
         * All keys in this mode are authorized for use as soon as the user unlocks the secure lock
         * screen or confirms their secure lock screen credential using the
         * KeyguardManager.createConfirmDeviceCredentialIntent flow.
         * The duration for which the authorization remains valid is specific to each key,
         * as specified using setUserAuthenticationValidityDurationSeconds during key generation or import.
         * Such keys can only be generated or imported if the secure lock screen is enabled
         * (see KeyguardManager.isDeviceSecure()).
         * These keys become permanently invalidated once the secure lock screen is disabled
         * (reconfigured to None, Swipe or other mode which does not authenticate the user)
         * or forcibly reset (e.g. by a Device Administrator).
         */
        AUTHENTICATION,
        /** Ask for a secific password at safe and  unsafe.Not supported at the moment.*/
        PASSWORD
    }

}
