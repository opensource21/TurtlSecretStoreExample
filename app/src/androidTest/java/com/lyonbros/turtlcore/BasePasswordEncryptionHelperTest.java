package com.lyonbros.turtlcore;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class BasePasswordEncryptionHelperTest {
    private static final Random random = new SecureRandom();

    @Test
    public void enAndDecrypt_Null() throws Exception {
        try {
            testWithPassword(null);
            fail("MissingPasswordException should be thrown.");
        } catch (BasePasswordEncryptionHelper.MissingPasswordException e) {
            // Expected
        }
    }

    @Test
    public void enAndDecrypt_1234() throws Exception {
        testWithPassword("1234");
    }

    @Test
    public void enAndDecrypt_Long() throws Exception {
        testWithPassword("1234567890öäß!\"§$%&/()=?<>|yxcvbnm,.;:@€µ");
    }

    private void testWithPassword(final String password) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, BasePasswordEncryptionHelper.MissingPasswordException {
        final BasePasswordEncryptionHelper testee = new BasePasswordEncryptionHelper() {
            @Override
            String getPassword() {
                return password;
            }
        };
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertArrayEquals(bytes, testee.decrypt(testee.encrypt(bytes)));
    }
}