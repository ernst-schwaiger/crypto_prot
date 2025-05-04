# Merkle Signatures
Group 3: Lorenzo Haidinger, Samuel Kominek, Stefan Ohnewith, Ernst Schwaiger

Implementation of a Merkle Tree using One-Time Lamport Key Pairs for signing messages-

## Preconditions

- JDK installed, e.g. OpenJDK 21
- gradle 8.x installed, see https://gradle.org/install/ (Version 4.x, like installed on Ubuntu, won't work!)

## Build and run

To build the project and run all tests:

```bash
cd crypto_prot/merkle
./gradlew build
```

## Run Attack Scenarios

### Run OTS Re-Use Attack

Build the project, then run 

```bash
./gradlew test --tests net.its26.OTSReuse.testOTSReuse
```

### Run Key Recovery Attack with SHA-256

Build the project, then run 

```bash
./gradlew task runKeyRecoveryAttack
```
