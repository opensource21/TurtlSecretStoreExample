package com.lyonbros.turtlcore;

public class FixPasswordEncryptionHelper extends BasePasswordEncryptionHelper {

    private final String fixPassword;

    public FixPasswordEncryptionHelper(String fixPassword) {
        this.fixPassword = fixPassword;
    }

    @Override
    String getPassword() {
        return fixPassword;
    }
}
