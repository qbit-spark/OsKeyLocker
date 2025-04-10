# 🗝️ OsSecureStore

[![](https://jitpack.io/v/qbit-spark/OsSecureStore.svg)](https://jitpack.io/#qbit-spark/OsSecureStore)

**OsSecureStore** is a cross-platform secure storage library for Java applications that leverages native OS-level security to safely store sensitive data like API keys, passwords, tokens, and credentials — without managing encryption keys yourself.

---

## ✨ Features

- 🔒 **OS-native security** – Currently supports Windows DPAPI (macOS & Linux support coming soon)
- 🧩 **Simple API** – Easy-to-use Java interface for storing and retrieving secure values
- 🧠 **Smart app detection** – Automatically detects application name for storage context
- 📂 **Flexible storage** – Organize data using key-value pairs or grouped namespaces
- 🔗 **JNI integration** – Securely connects to Windows DPAPI for robust native encryption

---

## 📦 Installation

### Using JitPack

To use **OsSecureStore** in your project, you can choose between **Maven** or **Gradle** as your build system.

#### **For Maven users**:

1. Add JitPack repository to your `pom.xml`:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

2. Then add the dependency:

```xml
<dependencies>
    <dependency>
        <groupId>com.github.qbit-spark</groupId>
        <artifactId>OsSecureStore</artifactId>
        <version>v1.0.2</version>
    </dependency>
</dependencies>
```

#### **For Gradle users**:

1. Add JitPack repository to your `build.gradle`:

```groovy
repositories {
    maven { url "https://jitpack.io" }
}
```

2. Then add the dependency:

```groovy
dependencies {
    implementation 'com.github.qbit-spark:OsSecureStore:v1.0.2'
}
```

---

## 🚀 Quick Start

### Basic Usage

```java
// Store a sensitive value
OsSecureStore.store("github.api_key", "ghp_1234567890abcdefghijklmnopqrstuvwxyz");

// Retrieve the value
String apiKey = OsSecureStore.retrieve("github.api_key");

// Check if the key exists
boolean exists = OsSecureStore.exists("github.api_key");

// Remove a specific key
OsSecureStore.remove("github.api_key");

// Clear all stored data
OsSecureStore.clear();
```

### Using `SecureDataManager`

Organize related credentials using namespaces:

```java
// Create a manager with a namespace
SecureDataManager authManager = new SecureDataManager("authentication");

// Store individual credentials
authManager.storeValue("username", "user@example.com");
authManager.storeValue("password", "MyS3cur3P@ssw0rd!");

// Store grouped OAuth tokens
Map<String, String> oauthTokens = SecureDataManager.createAuthCredentials(
    "access-token-value", 
    "refresh-token-value"
);
authManager.storeValueGroup("google", oauthTokens);

// Retrieve values
String username = authManager.loadValue("username");
String googleAccessToken = authManager.loadValue("google.access");
```

Set a custom application name (optional):

```java
OsSecureStore.setApplicationName("MyApplication");
```

---

## ⚙️ How It Works

OsSecureStore encrypts data using **platform-native security features**, then stores it in a local encrypted file. Your app never handles encryption keys directly.

| Platform | Backend Used | Notes |
|----------|--------------|-------|
| Windows  | [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API) | Fully supported |
| macOS    | [Keychain Services](https://developer.apple.com/documentation/security/keychain_services) | Coming soon |
| Linux    | [libsecret](https://wiki.gnome.org/Projects/Libsecret), Secret Service API | Coming soon |

### ✅ Benefits

- Encryption keys never leave the OS
- Data is tied to the current user profile
- No need to manage custom encryption logic

---

## 💻 Platform Support

- **Windows** – Fully supported
- **macOS** – Coming soon
- **Linux** – Coming soon

---

## 🔐 Security Considerations

- On Windows, encrypted data can only be accessed by the same user on the same machine
- For extra protection, consider an additional encryption layer for critical data
- Always use namespaces and meaningful key names to structure sensitive information

---

## 🤝 Contributing

We welcome contributions! You can:

- Add support for macOS or Linux
- Improve documentation
- Report bugs or vulnerabilities
- Suggest enhancements
- Submit pull requests

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for full details.

---
