# MQV
Group 3: Lorenzo Haidinger, Samuel Kominek, Stefan Ohnewith, Ernst Schwaiger

Menezes Qu Vanstone

## Preconditions

- OpenSSL installed
- OpenJDK 21 installed
- gradle 8.x installed, see https://gradle.org/install/ (Version 4.x, like installed on Ubuntu, won't work!)

## Build and run

To build the Project:
```bash
./gradlew build
```

To Start Bob (listener):
```bash
./gradlew :bob:run
```
Bob waits for a message from Alice


To Start Alice (sender):
```bash
./gradlew :alice:run
```
- Alice initiates the session by sending the session key.
- Bob responds by sending his session key.
- Both parties display the calculated secrets.

