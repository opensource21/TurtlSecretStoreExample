package com.lyonbros.turtlcore;

import android.os.Looper;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SecurityStoreTest {

    private static final Random random = new SecureRandom();
    private static final String TURTL_KEY = "TURTL_KEY";

    private SecurityStore testee;

    @BeforeClass
    public static  void setupClass() {
        Looper.prepare();
    }


    @Before
    public void setup() {
        testee = new SecurityStore(InstrumentationRegistry.getContext(), new FixPasswordEncryptionHelper("TODO"));
    }

    @Test
    public void storeAndLoadKeyNone() {
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertTrue(testee.storeKey(bytes, TURTL_KEY, "NONE"));
        assertArrayEquals(bytes, testee.loadKey(TURTL_KEY));
    }

    @Test
    @Ignore // Can't authenticate user in test.
    // see https://github.com/googlesamples/android-ConfirmCredential/blob/master/Application/src/main/java/com/example/android/confirmcredential/MainActivity.java
    // and https://blog.xamarin.com/easily-authenticate-users-with-androids-confirm-credential/
    // This must be done in the program :-(
    public void storeAndLoadKeyAuthentication() {
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertTrue(testee.storeKey(bytes, TURTL_KEY, "AUTHENTICATION"));
        assertArrayEquals(bytes, testee.loadKey(TURTL_KEY));
    }

    @Test
    public void storeAndLoadKeyPassword() {
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertTrue(testee.storeKey(bytes, TURTL_KEY, "PASSWORD"));
        assertArrayEquals(bytes, testee.loadKey(TURTL_KEY));
    }

}