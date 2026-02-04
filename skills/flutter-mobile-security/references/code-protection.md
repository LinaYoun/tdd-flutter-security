# Source Code Protection

This document covers techniques to protect your Flutter application's source code from reverse engineering and tampering.

## Overview

Code protection involves:
1. **Obfuscation** - Making code difficult to read
2. **Minification** - Reducing code size and removing debug info
3. **Log removal** - Preventing information leakage
4. **Secret management** - Avoiding hardcoded sensitive data

## Flutter Obfuscation

### Enabling Obfuscation

Flutter provides built-in obfuscation for release builds:

```bash
# Build with obfuscation
flutter build apk --release \
  --obfuscate \
  --split-debug-info=build/debug-info

# For App Bundle
flutter build appbundle --release \
  --obfuscate \
  --split-debug-info=build/debug-info
```

### What Obfuscation Does

- Renames classes, methods, and fields to meaningless names
- Removes symbol names from the compiled binary
- Makes reverse engineering significantly harder

**Before obfuscation:**
```dart
class UserAuthenticationService {
  Future<User> authenticateWithCredentials(String email, String password) {
    // ...
  }
}
```

**After obfuscation (decompiled):**
```dart
class a {
  Future<b> c(String d, String e) {
    // ...
  }
}
```

### Preserving Debug Information

The `--split-debug-info` flag saves symbol mapping for crash reporting:

```bash
flutter build apk --release \
  --obfuscate \
  --split-debug-info=build/debug-info/v1.0.0
```

**Important:** Keep these files secure and version them for each release.

### Symbolication for Crash Reports

To decode obfuscated stack traces:

```bash
flutter symbolize \
  -i crash_stack_trace.txt \
  -d build/debug-info/v1.0.0
```

## Android ProGuard/R8

### Enabling ProGuard/R8

In `android/app/build.gradle`:

```groovy
android {
    buildTypes {
        release {
            // Enable code shrinking and obfuscation
            minifyEnabled true
            shrinkResources true

            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

### ProGuard Rules

Create `android/app/proguard-rules.pro`:

```proguard
# Flutter specific rules
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }
-dontwarn io.flutter.embedding.**

# Keep annotations
-keepattributes *Annotation*

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Parcelables
-keepclassmembers class * implements android.os.Parcelable {
    static ** CREATOR;
}

# Keep Serializable classes
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}
```

### R8 (Default in AGP 3.4+)

R8 is enabled by default in Android Gradle Plugin 3.4+. No additional configuration needed.
It combines:
- ProGuard-compatible shrinking
- Desugaring
- Dexing

**Note:** The `android.enableR8.fullMode=true` flag was removed in AGP 4.0+.
In modern AGP versions, simply setting `minifyEnabled true` automatically enables R8 optimization.
No additional gradle.properties configuration is needed.

## Log Removal

### Debug Mode Checking

```dart
import 'package:flutter/foundation.dart';

void logDebugInfo(String message) {
  // Only log in debug mode
  if (kDebugMode) {
    print('DEBUG: $message');
  }
}

void logSensitiveOperation(String operation) {
  // Never log sensitive operations in release
  if (kDebugMode) {
    debugPrint('Operation: $operation');
  }
}
```

### Logger with Build Mode Awareness

```dart
import 'package:flutter/foundation.dart';

class AppLogger {
  static void debug(String message) {
    if (kDebugMode) {
      print('[DEBUG] $message');
    }
  }

  static void info(String message) {
    if (kDebugMode) {
      print('[INFO] $message');
    }
  }

  static void error(String message, [Object? error, StackTrace? stackTrace]) {
    if (kDebugMode) {
      print('[ERROR] $message');
      if (error != null) print('Error: $error');
      if (stackTrace != null) print('Stack: $stackTrace');
    }

    // In release mode, send to crash reporting service
    if (kReleaseMode) {
      // FirebaseCrashlytics.instance.recordError(error, stackTrace);
    }
  }

  static void warning(String message) {
    if (kDebugMode) {
      print('[WARN] $message');
    }
  }
}
```

### Removing All Debug Prints

Search and remove all debug statements before release:

**Unix/macOS/Git Bash:**
```bash
# Find all print statements
grep -rn "print(" lib/

# Find debugPrint statements
grep -rn "debugPrint(" lib/

# Find developer.log calls
grep -rn "developer.log" lib/
```

**Windows (PowerShell):**
```powershell
# Find all print statements
Get-ChildItem -Path lib -Recurse -Filter *.dart | Select-String "print\("

# Find debugPrint statements
Get-ChildItem -Path lib -Recurse -Filter *.dart | Select-String "debugPrint\("

# Find developer.log calls
Get-ChildItem -Path lib -Recurse -Filter *.dart | Select-String "developer.log"
```

**Windows (CMD):**
```cmd
:: Find all print statements
findstr /s /n "print(" lib\*.dart

:: Find debugPrint statements
findstr /s /n "debugPrint(" lib\*.dart

:: Find developer.log calls
findstr /s /n "developer.log" lib\*.dart
```

### Conditional Compilation

```dart
import 'dart:developer' as developer;

void log(String message) {
  // This code is completely removed in release builds
  assert(() {
    developer.log(message);
    return true;
  }());
}
```

## Hardcoded Secrets Detection

### Common Patterns to Avoid

```dart
// BAD: Hardcoded API keys
const String apiKey = 'sk-1234567890abcdef';  // INSECURE!
const String secretKey = 'my-secret-key-123';  // INSECURE!

// BAD: Hardcoded credentials
final String username = 'admin';      // INSECURE!
final String password = 'password123'; // INSECURE!

// BAD: Hardcoded URLs with keys
final url = 'https://api.example.com?key=SECRET';  // INSECURE!
```

### Secure Secret Management

#### Using Environment Variables

> **⚠️ WARNING: flutter_dotenv should NOT be used for sensitive secrets!**
>
> `flutter_dotenv` includes `.env` files in your app's assets bundle.
> Assets bundled in APK/IPA can be easily extracted, so
> **NEVER store API keys, passwords, or auth tokens in .env files!**
>
> **Appropriate uses:** Environment differentiation (dev/staging/prod), public configuration values only
>
> **For sensitive secrets:**
> 1. Receive them from server after authentication and store in `flutter_secure_storage`
> 2. Inject at build time with `--dart-define` — **⚠️ 비밀 저장에 부적합!** 바이너리에서 추출 가능하므로 공개 설정에만 사용
> 3. Prefer architectures that don't store secrets on the client

```yaml
# pubspec.yaml
dependencies:
  flutter_dotenv: ^5.1.0
```

Create `.env` file (add to `.gitignore`):
```
# ⚠️ Only for PUBLIC, non-sensitive configuration!
# NEVER put API keys, passwords, or tokens here!
BASE_URL=https://api.example.com
ENVIRONMENT=production
```

```dart
import 'package:flutter_dotenv/flutter_dotenv.dart';

Future<void> main() async {
  await dotenv.load(fileName: '.env');
  runApp(MyApp());
}

// ⚠️ Only access non-sensitive configuration
final baseUrl = dotenv.env['BASE_URL'] ?? '';
final environment = dotenv.env['ENVIRONMENT'] ?? 'development';
```

#### Secure Storage for Runtime Secrets

```dart
class SecretManager {
  final FlutterSecureStorage _storage;

  SecretManager(this._storage);

  // Store secret received from server
  Future<void> storeApiKey(String key) async {
    await _storage.write(key: 'api_key', value: key);
  }

  // Retrieve secret
  Future<String?> getApiKey() async {
    return await _storage.read(key: 'api_key');
  }
}
```

### Automated Secret Detection

Create a pre-commit hook or CI check:

**Unix/macOS/Git Bash:**
```bash
#!/bin/bash
# check-secrets.sh

# Patterns that might indicate hardcoded secrets
PATTERNS=(
    'api[_-]?key\s*[:=]'
    'secret[_-]?key\s*[:=]'
    'password\s*[:=]'
    'token\s*[:=]'
    'private[_-]?key'
    'BEGIN RSA PRIVATE KEY'
    'BEGIN OPENSSH PRIVATE KEY'
)

FOUND=0

for pattern in "${PATTERNS[@]}"; do
    results=$(grep -rniE "$pattern" lib/ --include="*.dart" 2>/dev/null)
    if [ -n "$results" ]; then
        echo "Potential secret found matching pattern: $pattern"
        echo "$results"
        FOUND=1
    fi
done

if [ $FOUND -eq 1 ]; then
    echo "WARNING: Potential hardcoded secrets detected!"
    exit 1
fi

echo "No hardcoded secrets detected."
exit 0
```

**Windows (PowerShell):**
```powershell
# check-secrets.ps1
$patterns = @(
    'api[_-]?key\s*[:=]',
    'secret[_-]?key\s*[:=]',
    'password\s*[:=]',
    'token\s*[:=]',
    'private[_-]?key',
    'BEGIN RSA PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY'
)

$found = $false
foreach ($pattern in $patterns) {
    $results = Get-ChildItem -Path lib -Recurse -Filter *.dart | Select-String -Pattern $pattern
    if ($results) {
        Write-Host "Potential secret found matching pattern: $pattern"
        $results | ForEach-Object { Write-Host $_.ToString() }
        $found = $true
    }
}

if ($found) {
    Write-Host "WARNING: Potential hardcoded secrets detected!" -ForegroundColor Red
    exit 1
}

Write-Host "No hardcoded secrets detected." -ForegroundColor Green
exit 0
```

## Build Configuration Security

### Complete build.gradle Security Settings

```groovy
android {
    compileSdk 34

    defaultConfig {
        minSdk 23
        targetSdk 34
    }

    buildTypes {
        debug {
            debuggable true
            minifyEnabled false
        }

        release {
            debuggable false
            minifyEnabled true
            shrinkResources true

            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'

            // Sign with release key
            signingConfig signingConfigs.release
        }
    }

    // Disable debugging in release
    buildFeatures {
        buildConfig true
    }
}
```

## Best Practices Summary

1. **Always obfuscate release builds**
   ```bash
   flutter build apk --release --obfuscate --split-debug-info=build/debug-info
   ```

2. **Enable ProGuard/R8 for Android**
   ```groovy
   minifyEnabled true
   shrinkResources true
   ```

3. **Remove all debug logs**
   ```dart
   if (kDebugMode) { print('debug'); }
   ```

4. **Never hardcode secrets**
   - Use environment variables or secure storage
   - Implement secret scanning in CI/CD

5. **Store debug symbols securely**
   - Keep `--split-debug-info` output for crash symbolication
   - Version symbols with each release

위의 `build.gradle` 및 `proguard-rules.pro` 예시를 참조하여 릴리스 빌드 보안을 구성하세요.
