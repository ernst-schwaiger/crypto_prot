# Needham-Schroeder
Group 3: Lorenzo Haidinger, Samuel Kominek, Stefan Ohnewith, Ernst Schwaiger

Implements the Needham-Schroeder protocol, as outlined in [Wikipedia](https://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol).


## Preconditions

- OpenJDK 21 installed
- gradle 8.x installed, see https://gradle.org/install/ (Version 4.x, like installed on Ubuntu, won't work!)

## Build and run

To build the Project:
```bash
./gradlew build
```

To start the server (listener):
```bash
./gradlew :server:run
```

To start bob (listener):
```bash
./gradlew :bob:run
```

Both server node and Bob are listening for a request from Alice

To start Alice (sender):
```bash
./gradlew :alice:run
```
