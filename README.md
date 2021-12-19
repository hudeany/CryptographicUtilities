# CryptographicUtilities
Examples and HowTos for BouncyCastle and Java Cryptography Extension (JCE)

See class "/src/main/java/de/soderer/utilities/crypto/CryptographicUtilities.java" for handling of symmetric and asymmetric keys.

## Asymmetric Encryption
See classes "/src/main/java/de/soderer/utilities/crypto/Asymmetric*Worker.java" for asymmetric enryption/decryption and signing/verification of data.

## Symmetric Encryption
See classes "/src/main/java/de/soderer/utilities/crypto/Symmetric*Worker.java" for symmetric enryption/decryption of data.

## Testing
JUnit 4 tests included in "/src/test/de/soderer/utilities/crypto/CryptographicUtilitiesTest.java".

## Dependencies
Of course this project has dependencies. I tested with OpenJDK Java 11 and this current BouncyCastle versions of libs:
- bcpkix-jdk15on-1.69.jar
- bcprov-jdk15on-1.69.jar
- bcutil-jdk15on-1.69.jar
