package com.lyonbros.turtlcore;

class FixPasswordEncryptionHelper extends BasePasswordEncryptionHelper {

    private final String fixPassword;

    FixPasswordEncryptionHelper(String fixPassword) {
        this.fixPassword = fixPassword;
    }

    @Override
    String getPassword() {
        return fixPassword;
    }
}
