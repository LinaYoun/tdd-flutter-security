# Data Storage Security

This document covers secure data storage practices for Flutter Android applications.

**Note:** 이 문서는 Android 전용입니다. (This document is Android-only.)

## Storage Options Overview

| Storage Method | Security Level | Use Case |
|---------------|----------------|----------|
| SharedPreferences | Low | Non-sensitive settings |
| flutter_secure_storage | High | Credentials, tokens, keys |
| SQLite (unencrypted) | Low | Non-sensitive structured data |
| SQLite (encrypted) | High | Sensitive structured data |
| File storage | Varies | Depends on implementation |

## SharedPreferences Security

### What NOT to Store

Never store these in SharedPreferences:
- API keys or tokens
- Passwords or PINs
- Personal identification information
- Financial data
- Session tokens
- Encryption keys

### Why SharedPreferences is Insecure

On rooted devices, SharedPreferences XML files are accessible:
```
/data/data/com.example.app/shared_prefs/
```

Even on non-rooted devices, ADB backup can extract this data if `allowBackup="true"`.

### Safe SharedPreferences Usage

```dart
import 'package:shared_preferences/shared_preferences.dart';

// SAFE: Non-sensitive preferences only
final prefs = await SharedPreferences.getInstance();
await prefs.setBool('onboarding_completed', true);
await prefs.setString('theme_mode', 'dark');
await prefs.setInt('items_per_page', 20);

// NEVER DO THIS:
// await prefs.setString('auth_token', token);  // INSECURE!
// await prefs.setString('password', password); // INSECURE!
```

## flutter_secure_storage

### Installation

> **📦 Version Note**: 아래 버전은 참조용 예시입니다. 최신 안정 버전은 [pub.dev](https://pub.dev)에서 확인하세요.

```yaml
dependencies:
  flutter_secure_storage: ^9.0.0
```

### How It Works (Android)

- **Android**: Uses EncryptedSharedPreferences (Android Keystore)
- 암호화 키는 Android Keystore에 안전하게 저장됩니다 (Encryption keys are securely stored in Android Keystore)

### Basic Usage

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorageService {
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
    ),
  );

  // Store sensitive data
  Future<void> saveToken(String token) async {
    await _storage.write(key: 'auth_token', value: token);
  }

  // Retrieve sensitive data
  Future<String?> getToken() async {
    return await _storage.read(key: 'auth_token');
  }

  // Delete sensitive data
  Future<void> deleteToken() async {
    await _storage.delete(key: 'auth_token');
  }

  // Clear all secure data (e.g., on logout)
  Future<void> clearAll() async {
    await _storage.deleteAll();
  }

  // Check if key exists
  Future<bool> hasToken() async {
    return await _storage.containsKey(key: 'auth_token');
  }
}
```

### Android-Specific Configuration

For Android, configure in `android/app/build.gradle`:

```groovy
android {
    defaultConfig {
        minSdk 23  // Required for EncryptedSharedPreferences
    }
}
```

**Note:** Recent Flutter versions prefer `minSdk` syntax over deprecated `minSdkVersion`. Check your Flutter version's migration guide for the recommended syntax.

## Database Encryption

### Using sqlcipher_flutter_libs

For SQLite encryption with the `drift` package:

> **📦 Version Note**: 아래 버전은 참조용 예시입니다. 최신 안정 버전은 [pub.dev](https://pub.dev)에서 확인하세요.

```yaml
dependencies:
  drift: ^2.14.0
  sqlcipher_flutter_libs: ^0.6.0

dev_dependencies:
  drift_dev: ^2.14.0
```

### ✅ Secure Key Management (REQUIRED)

**Never hardcode encryption keys.** Always retrieve keys from secure storage:

```dart
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:drift/drift.dart';
import 'package:drift/native.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sqlcipher_flutter_libs/sqlcipher_flutter_libs.dart';
import 'package:sqlite3/open.dart';

class EncryptedDatabaseService {
  final _secureStorage = const FlutterSecureStorage();

  Future<String> _getOrCreateDatabaseKey() async {
    String? key = await _secureStorage.read(key: 'db_encryption_key');

    if (key == null) {
      // Generate new key (32 bytes = 256-bit AES)
      final random = Random.secure();
      final keyBytes = List<int>.generate(32, (_) => random.nextInt(256));
      key = base64Encode(keyBytes);
      await _secureStorage.write(key: 'db_encryption_key', value: key);
    }

    return key;
  }

  LazyDatabase openSecureDatabase() {
    return LazyDatabase(() async {
      // Set up SQLCipher
      await applyWorkaroundToOpenSqlCipherOnOldAndroidVersions();
      open.overrideFor(OperatingSystem.android, openCipherOnAndroid);

      // Get key from secure storage (NOT hardcoded!)
      final encryptionKey = await _getOrCreateDatabaseKey();

      final dbFile = await getApplicationDocumentsDirectory()
          .then((dir) => File('${dir.path}/secure_app.db'));

      return NativeDatabase.createInBackground(
        dbFile,
        setup: (database) {
          // Use dynamically retrieved key
          database.execute("PRAGMA key = '$encryptionKey'");
        },
      );
    });
  }
}
```

### ❌ Incorrect Example (DO NOT COPY)

> **🚫 WARNING: The following code is INSECURE!**
>
> Never hardcode encryption keys. This example shows what NOT to do.
> Hardcoded keys can be extracted through reverse engineering.

```dart
// BAD: Hardcoded key - DO NOT USE!
LazyDatabase _openDatabase() {
  return LazyDatabase(() async {
    await applyWorkaroundToOpenSqlCipherOnOldAndroidVersions();
    open.overrideFor(OperatingSystem.android, openCipherOnAndroid);

    final dbFile = await getApplicationDocumentsDirectory()
        .then((dir) => File('${dir.path}/secure_app.db'));

    return NativeDatabase.createInBackground(
      dbFile,
      setup: (database) {
        // ❌ INSECURE: Hardcoded key can be extracted!
        database.execute("PRAGMA key = 'your-encryption-key'");
      },
    );
  });
}
```

## File Storage Security

### Internal Storage (Private)

```dart
import 'dart:io';
import 'package:path_provider/path_provider.dart';

Future<File> savePrivateFile(String filename, String content) async {
  final directory = await getApplicationDocumentsDirectory();
  final file = File('${directory.path}/$filename');

  // File is only accessible by this app
  return file.writeAsString(content);
}
```

### Encrypting File Contents

**중요 주의사항 (Important Notes):**
1. **IV 재사용 금지 (Never Reuse IV)**: 같은 키로 동일한 IV를 절대 재사용하지 마세요 (Never reuse the same IV with the same key)
2. **키 관리 (Key Management)**: 암호화 키는 반드시 flutter_secure_storage에 저장 (Always store encryption keys in flutter_secure_storage)
3. **init() 호출 필수 (init() Required)**: 사용 전 반드시 init()을 호출해야 합니다 (Must call init() before use)
4. **에러 처리 (Error Handling)**: 복호화 실패 시 적절한 에러 처리 필요 (Handle decryption failures appropriately)

**Recommended Package:**

> **📦 Version Note**: 아래 버전은 참조용 예시입니다. 최신 안정 버전은 [pub.dev](https://pub.dev)에서 확인하세요.

```yaml
dependencies:
  cryptography: ^2.9.0
  cryptography_flutter: ^2.3.4  # Optional: native acceleration
  flutter_secure_storage: ^9.0.0
```

> **Why `cryptography` instead of `encrypt`?**
> - The `encrypt` package uses AES-CBC by default, which lacks integrity verification
> - AES-GCM (Galois/Counter Mode) provides AEAD (Authenticated Encryption with Associated Data)
> - AEAD ensures both confidentiality AND integrity - tampered ciphertext is detected
> - Reference: https://pub.dev/packages/cryptography

```dart
import 'dart:convert';
import 'dart:io';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// AES-256-GCM provides both confidentiality and integrity (AEAD).
/// Unlike AES-CBC, it detects tampering and prevents padding oracle attacks.
class EncryptedFileService {
  static final _algorithm = AesGcm.with256bits();
  final FlutterSecureStorage _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  SecretKey? _key;
  bool _initialized = false;

  /// 서비스 초기화 - 사용 전 반드시 호출해야 합니다
  ///
  Future<void> init() async {
    if (_initialized) return;

    String? storedKey = await _storage.read(key: 'encryption_key');
    if (storedKey == null) {
      // 새 키 생성 (256비트 AES-GCM)
      _key = await _algorithm.newSecretKey();
      final keyBytes = await _key!.extractBytes();
      await _storage.write(key: 'encryption_key', value: base64Encode(keyBytes));
    } else {
      _key = SecretKey(base64Decode(storedKey));
    }
    _initialized = true;
  }

  Future<void> saveEncryptedFile(String path, String content) async {
    _ensureInitialized();

    // AES-GCM automatically generates a random nonce
    final secretBox = await _algorithm.encrypt(
      utf8.encode(content),
      secretKey: _key!,
    );

    // Format: nonce:ciphertext:mac (all base64)
    // MAC (Message Authentication Code) enables tamper detection
    final file = File(path);
    await file.writeAsString(
      '${base64Encode(secretBox.nonce)}:'
      '${base64Encode(secretBox.cipherText)}:'
      '${base64Encode(secretBox.mac.bytes)}'
    );
  }

  Future<String> readEncryptedFile(String path) async {
    _ensureInitialized();

    final file = File(path);
    final data = await file.readAsString();
    final parts = data.split(':');

    if (parts.length != 3) {
      throw FormatException('Invalid encrypted file format');
    }

    final secretBox = SecretBox(
      base64Decode(parts[1]),  // cipherText
      nonce: base64Decode(parts[0]),
      mac: Mac(base64Decode(parts[2])),
    );

    // decrypt() throws SecretBoxAuthenticationError if MAC verification fails
    // This detects tampering - a key advantage over AES-CBC
    final decrypted = await _algorithm.decrypt(secretBox, secretKey: _key!);
    return utf8.decode(decrypted);
  }

  void _ensureInitialized() {
    if (!_initialized || _key == null) {
      throw StateError('EncryptedFileService not initialized. Call init() first.');
    }
  }
}
```

## Cache Security

### Clear Sensitive Cache on Logout

```dart
Future<void> clearSensitiveData() async {
  // Clear secure storage
  final secureStorage = FlutterSecureStorage();
  await secureStorage.deleteAll();

  // Clear cache directory
  final cacheDir = await getTemporaryDirectory();
  if (cacheDir.existsSync()) {
    cacheDir.deleteSync(recursive: true);
  }

  // Clear application documents if needed
  final appDir = await getApplicationDocumentsDirectory();
  final sensitiveFiles = ['user_data.json', 'session.db'];
  for (final filename in sensitiveFiles) {
    final file = File('${appDir.path}/$filename');
    if (file.existsSync()) {
      file.deleteSync();
    }
  }
}
```

## Best Practices Summary

1. **Classify Data Sensitivity**
   - Public: Can use any storage
   - Internal: Use private storage with proper permissions
   - Confidential: Must use encrypted storage

2. **Use Appropriate Storage**
   - Credentials → flutter_secure_storage
   - Sensitive DB → Encrypted SQLite
   - Settings → SharedPreferences (non-sensitive only)

3. **Implement Secure Deletion**
   - Clear all sensitive data on logout
   - Implement session timeout with data clearing

4. **Key Management**
   - Never hardcode encryption keys
   - Use secure key derivation
   - Store keys in secure storage

5. **Backup Exclusion**
   - Set `allowBackup="false"` or exclude sensitive files

위의 코드 예시들을 참조하여 앱의 데이터 민감도에 맞는 저장 방식을 선택하세요.
