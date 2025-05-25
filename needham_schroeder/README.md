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

### Run Needham-Schroeder without attack

Start the server (listener):
```bash
./gradlew :server:run
```

Start bob (listener):
```bash
./gradlew :bob:run
```

Both server node and Bob are listening for a request from Alice

Start Alice (sender):
```bash
./gradlew :alice:run
```

If successful, Alice should receive an encrypted message from Bob, which Alice can decrypt to
``Session Key accepted and verified Alices identity at: <date-time>``

### Run Needham-Schroeder with attack

Start bob (listener):
```bash
./gradlew :bob:run
```

Bob is listening for a request from Alice

Start Mallory (sender):
```bash
./gradlew :mallory:run
```

If successful, Mallory should receive an encrypted message from Bob, which Mallory can decrypt to
``Session Key accepted and verified Alices identity at: <date-time>``
