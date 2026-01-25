# Android CTA Keystore Integration (Mock)

## Goal
Demonstrate how HoboFrancs CTA certificates
can bind to Android’s keystore without root access.

## Flow (Concept)
1. Creator registers work
2. CTA manifest generated
3. Hash stored in Android Keystore
4. Certificate reference returned to user

## Pseudocode
KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
GenerateKeyPairSpec spec = new GenerateKeyPairSpec.Builder(context)
    .setAlias("HoboFrancs_CTA")
    .setSubject(new X500Principal("CN=Creator"))
    .build();

## Result
- Proof exists locally
- Non-exportable private key
- Verifiable public reference

## Future
- System installer hooks
- OEM keystore extensions
- Trust delegation APIs
