# 🗝️OsSecureStore

OsSecureStore is a cross-platform secure storage library for Java applications that leverages native OS security features to safely store sensitive data like API keys, tokens, passwords, and credentials.

## Features

- **OS-native security**: Uses platform-specific security APIs (currently Windows DPAPI, with macOS and Linux support coming soon)
- **Simple API**: Easy-to-use interface for storing and retrieving encrypted data
- **Automatic application name detection**: Intelligently identifies your application and creates appropriate storage locations
- **Flexible storage organization**: Store individual values or related groups of data with namespaces
- **JNI integration**: Seamlessly connects to Windows Data Protection API (DPAPI) for strong encryption

## Installation

### Using JitPack

Add the JitPack repository to your build file:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

Then add the dependency:

```xml
<dependencies>
    <dependency>
        <groupId>com.github.qbit-spark</groupId>
        <artifactId>OsSecureStore</artifactId>
        <version>v1.0.2</version>
    </dependency>
</dependencies>
```

## Quick Start

### Basic Usage

```java
// Store a sensitive API key
OsSecureStore.store("github.api_key", "ghp_1234567890abcdefghijklmnopqrstuvwxyz");

// Later, retrieve the key
String apiKey = OsSecureStore.retrieve("github.api_key");

// Check if a key exists
boolean hasKey = OsSecureStore.exists("github.api_key");

// Remove a key when no longer needed
OsSecureStore.remove("github.api_key");

// Clear all stored data
OsSecureStore.clear();
```

### Using SecureDataManager

For more organized credential management, use the `SecureDataManager` class:

```java
// Create a manager with a custom namespace
SecureDataManager authManager = new SecureDataManager("authentication");

// Store individual credentials
authManager.storeValue("username", "user@example.com");
authManager.storeValue("password", "MyS3cur3P@ssw0rd!");

// Store grouped credentials (e.g., OAuth tokens)
Map<String, String> oauthTokens = SecureDataManager.createAuthCredentials(
    "access-token-value-here",  // Access token
    "refresh-token-value-here"  // Refresh token
);
authManager.storeValueGroup("google", oauthTokens);

// Retrieve values
String username = authManager.loadValue("username");
String googleAccessToken = authManager.loadValue("google.access");
```

```java
OsSecureStore.setApplicationName("MyApplication");
```

## How It Works

OsSecureStore uses different mechanisms depending on the operating system:

- **Windows**: Windows Data Protection API (DPAPI), which ties the encryption to the current Windows user account
- **macOS**: (Coming soon)
- **Linux**: (Coming soon)

All values are encrypted before being stored in a properties file. The encryption is handled by the OS's native security APIs, ensuring that:

1. No encryption keys need to be managed by your application
2. The encrypted data can only be decrypted by the same user on the same machine
3. The security is handled at the OS level rather than relying on custom encryption algorithms

## Platform Support

- **Windows**: Fully supported via [Windows Data Protection API (DPAPI)](https://en.wikipedia.org/wiki/Data_Protection_API). DPAPI provides user account-based encryption that securely ties data to the current Windows user credentials.

- **macOS**: Coming soon - Will use macOS [Keychain Services](https://developer.apple.com/documentation/security/keychain_services) to securely store sensitive data. The Keychain is the macOS system for storing passwords, keys, certificates, and other secrets.

- **Linux**: Coming soon - Planning to implement support using [libsecret](https://wiki.gnome.org/Projects/Libsecret) and/or [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/), which provides secure storage through system services like GNOME Keyring or KDE Wallet.

## Contributing

Contributions are welcome! Here are some ways you can contribute:

- Implement support for additional platforms (macOS, Linux)
- Improve documentation
- Report bugs
- Suggest new features
- Submit pull requests

## Security Considerations

- The security of the stored data relies on the OS's native security features
- On Windows, data is tied to the specific Windows user account
- For highest security, consider implementing additional encryption layers for certain types of sensitive data

  ## License

This project is licensed under the MIT License - see the LICENSE file for details.
