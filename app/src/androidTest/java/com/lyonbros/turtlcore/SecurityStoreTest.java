package com.lyonbros.turtlcore;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SecurityStoreTest {

    private static final Random random = new SecureRandom();

    private SecurityStore testee;

    @Before
    public void setup() {
        testee = new SecurityStore(InstrumentationRegistry.getContext());
    }

    @Test
    public void storeAndLoadKey() {
        byte[] bytes = new byte[42];
        random.nextBytes(bytes);
        assertTrue(testee.storeKey(bytes, "NONE"));
        assertArrayEquals(bytes, testee.loadKey());
    }

}