# crypto_prot
Basic Cryptographic Protocols implemented in Java

## build and run tests
./gradlew build

## get test coverage via JaCoCo

./gradlew test jacocoTestReport

## TODO

- Add gradle task to generate keys and certificates as dependencies to Client and Server applications
- In Client/Sever app, use relative paths for reading in certs and keys
- Describe Client/Server Protocol
- Switch parser/generator functions to (De)Serializer class.
- FIXME in ClientServer.java: Potential Buffer overrun