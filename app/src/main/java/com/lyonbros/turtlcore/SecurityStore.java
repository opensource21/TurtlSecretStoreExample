package com.lyonbros.turtlcore;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

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

    private static final String TURTL_KEYSTORE_NAME = "TurtlKeyStore";
    private static final String TURTL_KEYSTORE_KEY = "TurtlLoginSecret";
    private static final String TURTL_CRYPTED_KEY = "TURTL_CRYPTED_KEY";
    private static final String TURTL_CRYPTED_IV = "TURTL_CRYPTED_IV";

    private final SharedPreferences preferences;

    /**
     * Initialize this object.
     * @param context the context of the android app. Can be get at Cordova-Plugin via <br>
     *                <code>this.cordova.getActivity().getApplicationContext();</code> otherwise
     *                each Activity is a valid context.
     */
    public SecurityStore(Context context) {
        this.preferences= PreferenceManager.getDefaultSharedPreferences(context);
    }


    public boolean storeKey(byte[] unencryptedKey, SecurityMode securityMode) {
        try {
            final Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, createSecretKey(securityMode));
            final byte[] iv = cipher.getIV();
            final byte[] crypteKey = cipher.doFinal(unencryptedKey);
            final SharedPreferences.Editor editor = preferences.edit();
            editor.putString(TURTL_CRYPTED_KEY, Base64.encodeToString(crypteKey, Base64.DEFAULT));
            editor.putString(TURTL_CRYPTED_IV, Base64.encodeToString(iv, Base64.DEFAULT));
            editor.apply();
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | NoSuchProviderException e) {
            Log.e(LOG_TAG_NAME,"Wrong encryption parameter", e);
        }
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
            final byte[] cryptedKey = Base64.decode(preferences.getString(TURTL_CRYPTED_KEY, null), Base64.DEFAULT);
            final byte[] encryptionIv = Base64.decode(preferences.getString(TURTL_CRYPTED_IV, null), Base64.DEFAULT);
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(CIPHER_MODE);
                final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
                return cipher.doFinal(cryptedKey);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                    InvalidAlgorithmParameterException | InvalidKeyException |
                    IllegalBlockSizeException | BadPaddingException e) {
                Log.e(LOG_TAG_NAME,"Wrong decryption parameter", e);
            }
        }
        return null;
    }

    @NonNull
    private SecretKey createSecretKey(SecurityMode securityMode) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {

        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, TURTL_KEYSTORE_NAME);

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
            final KeyStore keyStore = KeyStore.getInstance(TURTL_KEYSTORE_NAME);
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