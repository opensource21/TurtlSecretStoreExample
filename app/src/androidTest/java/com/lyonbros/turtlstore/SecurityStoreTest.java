package com.lyonbros.turtlstore;

import android.os.Looper;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

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
        testee = new SecurityStore(InstrumentationRegistry.getContext());
    }

    @Test
    public void storeAndLoadKey_CusttomKey() {
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertTrue(testee.storeKey(bytes, TURTL_KEY));
        assertArrayEquals(bytes, testee.loadKey(TURTL_KEY));
    }

    @Test
    public void storeAndLoadKey() {
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertTrue(testee.storeKey(bytes));
        assertArrayEquals(bytes, testee.loadKey());
    }
}