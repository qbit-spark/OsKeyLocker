# 🗝️OsKeylocker

[![](https://jitpack.io/v/qbit-spark/OsSecureStore.svg)](https://jitpack.io/#qbit-spark/OsSecureStore)

OsKeylocker is a robust, cross-platform Java library designed to provide secure credential management using native OS security features. The library enables developers to safely store sensitive information like API keys, OAuth tokens, passwords, and other credentials without the complexity of managing encryption infrastructure.

## Features

- **Native OS Security Integration**: Leverages Windows DPAPI with an additional layer of AES-GCM encryption
- **Intuitive Fluent API**: Modern builder pattern for clean, readable code
- **Package-Based Isolation**: Automatic isolation of credentials by application package
- **Large Data Support**: Automatic chunking mechanism that bypasses Windows Credential Manager's 2048-character limitation, allowing you to store credentials of unlimited size without any additional code.
- **Customizable Encryption**: Optional additional encryption layer with application-defined keys

## Installation

### Maven

Add the JitPack repository to your `pom.xml`:

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
        <version>{version}</version>
    </dependency>
</dependencies>
```

### Gradle

```groovy
repositories {
    maven { url "https://jitpack.io" }
}

dependencies {
    implementation 'com.github.qbit-spark:OsSecureStore:{version}'
}
```

## Usage

### Storing Credentials

```java
// Store API credentials
boolean success = SecureStorage.write()
    .to("github-api")
    .property("key", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    .property("username", "developer@organization.com")
    .execute();

// Store multiple properties with custom encryption
Map<String, Object> oauth = new HashMap<>();
oauth.put("access_token", "eyJ0eXAiOiJKV1QiLCJhbGc...");
oauth.put("refresh_token", "eyJhbGciOiJIUzI1NiIsInR5cCI...");
oauth.put("expires_in", 3600);
oauth.put("token_type", "Bearer");

SecureStorage.write()
    .withEncryption("application-specific-encryption-key") //This is requred at first and highly recommended derive it from multiple sources (user input + machine-specific information) PBKDF2, Argon2, or similar with high iteration counts
    .to("service-oauth")  //This is requred at second 
    .properties(oauth)
    .execute();
```

### Retrieving Credentials

```java
// Verify credential existence
boolean exists = SecureStorage.read()
    .from("github-api")
    .exists();

// Retrieve specific property
String apiKey = (String) SecureStorage.read()
    .from("github-api")
    .getProperty("key");

// Retrieve all properties with custom encryption
Map<String, Object> credentials = SecureStorage.read()
    .withEncryption("application-specific-encryption-key")
    .from("service-oauth")
    .getAllProperties();

// Access individual properties
String accessToken = (String) credentials.get("access_token");
Integer expiresIn = (Integer) credentials.get("expires_in");
```

### Removing Credentials

```java
// Delete credentials when no longer needed
SecureStorage.delete()
    .identifier("github-api")
    .execute();
```

## Security Architecture

SecureStorage implements a multi-layered security approach:

1. **Application Isolation Layer**: Credentials are namespaced by application package, preventing cross-application access
2. **Cryptographic Layer**: All data is encrypted using AES-GCM with unique initialization vectors
3. **OS Security Layer**: Windows Data Protection API provides OS-level encryption tied to user accounts
4. **Optional Application Layer**: Additional encryption using application-provided keys

This defense-in-depth strategy ensures data remains secure even if one security layer is compromised.

## Technical Details

### Data Storage Format

Credentials are stored in the following format:
```
OsSecureStore.[PackageName].[CredentialIdentifier]
```

Large credentials are automatically split into manageable chunks with metadata to track the structure:
```
OsSecureStore.[PackageName].[CredentialIdentifier].metadata
OsSecureStore.[PackageName].[CredentialIdentifier].CHUNK_0
OsSecureStore.[PackageName].[CredentialIdentifier].CHUNK_1
...
```

### Security Considerations

- Encryption keys should be securely managed and not hardcoded
- For highest security, use unique encryption keys for different credential sets
- Consider implementing key rotation policies for long-lived credentials
- The library does not provide network isolation; secure transmission is the application's responsibility

## API Reference

### Write Operations

```java
SecureStorage.write()
    .withEncryption(String)     // Requred: Custom encryption key
    .to(String)                 // Required: Credential identifier
    .property(String, Object)   // Add single property
    .properties(Map)            // Add multiple properties
    .execute()                  // Returns boolean success status
```

### Read Operations

```java
SecureStorage.read()
    .withEncryption(String)     // Requred: Must match write encryption
    .from(String)               // Required: Credential identifier
    .exists()                   // Returns boolean
    .getAllProperties()         // Returns Map<String, Object>
    .getProperty(String)        // Returns Object for specific key
```

### Delete Operations

```java
SecureStorage.delete()
    .identifier(String)         // Required: Credential identifier
    .execute()                  // Returns boolean success status
```

## Platform Support

- **Windows**: Full support
- **macOS**: Planned for future release
- **Linux**: Planned for future release

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
