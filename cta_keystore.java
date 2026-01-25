KeyPairGenerator kpg = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

kpg.initialize(
    new KeyGenParameterSpec.Builder(
        "HF_CTA_KEY",
        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setUserAuthenticationRequired(false)
    .build()
);

KeyPair keyPair = kpg.generateKeyPair();
