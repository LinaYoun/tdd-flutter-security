---
name: Flutter Android Security
description: This skill should be used when the user asks to "check Flutter app security", "secure Android app", "audit Android security", "check for hardcoded secrets", "configure SSL pinning", "enable obfuscation", "check AndroidManifest security", "Flutter 앱 보안 점검", "안드로이드 보안 설정", "앱 배포 전 보안 체크리스트", "API 키 하드코딩 점검", or needs guidance on Flutter Android security best practices based on KISA mobile security guidelines. Note: This skill is Android-only.
version: 1.1.0
---

# Flutter Android Security Guide

This skill provides comprehensive security guidance for Flutter Android applications based on the Korean Ministry of Public Administration and Security (MOIS) and KISA mobile security guidelines.

**Note:** 이 스킬은 Android 전용입니다. iOS 보안 가이드는 별도로 제공됩니다.
(This skill is Android-only. iOS security guide is provided separately.)

## Overview

Mobile application security encompasses multiple layers: platform configuration, data storage, network communication, and source code protection. This skill helps you audit and secure Flutter apps across all these dimensions.

## Quick Security Checklist

Before releasing your Flutter app, verify these critical items:

### Build Environment

> **📅 Update Policy**: 빌드 환경 요구사항은 Flutter/AGP/Gradle 릴리스마다 변경됩니다.
> 아래 내용은 참조용이며, 반드시 공식 문서를 확인하세요.
>
> **Source of Truth:**
> - [Flutter Release Notes](https://docs.flutter.dev/release/release-notes)
> - [AGP-Gradle-JDK Compatibility Matrix](https://developer.android.com/build/releases/gradle-plugin#updating-gradle)
> - [Flutter Android Java/Gradle Migration Guide](https://docs.flutter.dev/release/breaking-changes/android-java-gradle-migration-guide)

#### Build Environment Requirements

##### Java/Gradle 버전 (Flutter 3.38+ 기준)
- [ ] **JDK 버전**: AGP 9 사용 시 JDK 17 필수. 그 외 버전은 [AGP-Gradle-JDK Compatibility Matrix](https://developer.android.com/build/releases/gradle-plugin#updating-gradle) 참조
- [ ] **Gradle 버전**: Flutter/AGP 버전에 따라 요구사항 상이 - [AGP-Gradle-JDK Compatibility Matrix](https://developer.android.com/build/releases/gradle-plugin#updating-gradle) 참조
- [ ] Java 17 사용 시 Gradle 버전 호환성: [Flutter Android Java/Gradle Migration Guide](https://docs.flutter.dev/release/breaking-changes/android-java-gradle-migration-guide) 참조

##### AGP 호환성
- [ ] AGP-Gradle-JDK 호환성: [Android 공식 호환성 매트릭스](https://developer.android.com/build/releases/gradle-plugin#updating-gradle) 참조
- [ ] AGP 9.x 마이그레이션: [Flutter AGP 9 Migration Guide](https://docs.flutter.dev/release/breaking-changes/migrate-to-agp-9)

> **⚠️ AGP 9 마이그레이션 안내:**
> - Flutter의 AGP 9 완전 자동 지원은 진행 중이며, 현재는 수동 마이그레이션이 필요합니다.
> - 플러그인 사용 앱은 추가 설정이 필요할 수 있습니다.
> - 자세한 내용은 [Flutter AGP 9 Migration Guide](https://docs.flutter.dev/release/breaking-changes/migrate-to-agp-9) 참조.

- [ ] Variant API 변경 (AGP 9+): `Variant.minSdkVersion` → `minSdk`로 대체 ([AGP 9 Release Notes](https://developer.android.com/build/releases/agp-9-0-0-release-notes))

#### minSdk 권장 기준

| 요구사항 | 최소 SDK | 비고 |
|---------|---------|------|
| TLS 1.2 지원 | 21+ | 네트워크 보안 필수 |
| EncryptedSharedPreferences | 23+ | `flutter_secure_storage` 사용 시 |

> **권장:** 보안 저장소(`flutter_secure_storage`) 사용 시 minSdk 23+

### AndroidManifest.xml
- [ ] `android:allowBackup="false"` - ADB 백업 방지 (⚠️ targetSdk 31+ (Android 12+) 및 일부 제조사 기기에서는 device-to-device 이전을 완전히 차단하지 않음 - `dataExtractionRules`도 함께 설정 필요)
- [ ] Android 12+: `android:dataExtractionRules` 설정 - 클라우드 백업 및 device-to-device 이전 시 복사할 파일/디렉터리 규정 ([Android 문서](https://developer.android.com/guide/topics/manifest/application-element))
- [ ] `android:debuggable="false"` in release builds
- [ ] `android:usesCleartextTraffic="false"` 명시 - targetSdk 27 이하는 기본값이 `true` ([Android 문서](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic))
- [ ] All exported components explicitly declared with `android:exported`
- [ ] Minimum necessary permissions only

### Data Storage
- [ ] No sensitive data in SharedPreferences
- [ ] Using `flutter_secure_storage` for credentials/tokens
- [ ] Database encryption enabled for sensitive data
- [ ] File permissions set to MODE_PRIVATE

### Network Security
- [ ] All API calls use HTTPS
- [ ] SSL/TLS certificate validation enabled
- [ ] Certificate pinning implemented for critical endpoints
- [ ] Network security config blocks cleartext traffic

### Code Protection
- [ ] Obfuscation enabled (`--obfuscate --split-debug-info`)
- [ ] ProGuard/R8 configured for release builds
- [ ] All debug logs removed in release
- [ ] No hardcoded API keys, secrets, or passwords

### Platform Security
- [ ] Root detection implemented
- [ ] Implicit intents secured
- [ ] Sensitive broadcasts use secure alternatives (Provider, Stream, EventBus)

## Security Domains

### 1. AndroidManifest.xml Security

The AndroidManifest.xml is the first line of defense. Critical settings include:

```xml
<application
    android:allowBackup="false"
    android:debuggable="false"
    android:usesCleartextTraffic="false">
```

**Key Points:**
- `allowBackup="false"` prevents ADB backup data extraction attacks
- `debuggable="false"` prevents debugger attachment in production
- `usesCleartextTraffic="false"` enforces HTTPS-only communication
- Always explicitly set `android:exported` for all activities, services, and receivers

See: `references/android-manifest-security.md` for detailed configuration.

### 2. Data Storage Security

Never store sensitive information in plain text:

```dart
// BAD: Plain SharedPreferences
final prefs = await SharedPreferences.getInstance();
prefs.setString('token', userToken); // INSECURE!

// GOOD: Encrypted storage
final storage = FlutterSecureStorage();
await storage.write(key: 'token', value: userToken);
```

**Recommended Packages:**
- `flutter_secure_storage` - Keychain (iOS) / EncryptedSharedPreferences (Android)
- `sqlcipher_flutter_libs` - SQLite encryption
- `hive` with encryption - Encrypted NoSQL storage

See: `references/data-storage-security.md` for implementation details.

### 3. Network Security

All network communication must be encrypted and validated:

**Certificate Pinning (Android)**

> **⚠️ 중요 경고: `badCertificateCallback`의 한계**
>
> Dart의 `badCertificateCallback`은 **"인증서 오류 시에만"** 호출됩니다.
> 신뢰할 수 있는 CA(Let's Encrypt, DigiCert 등)에서 발급된 **유효한 인증서는
> 이 콜백을 트리거하지 않습니다.** 따라서 Dart 코드만으로는 실제 핀닝이 적용되지 않습니다!

**Scope note:** Dart-only checks (e.g., `badCertificateCallback` or Dart libraries) are not equivalent to Android `<pin-set>` pinning.
Treat Dart-only logic as supplementary detection only; do not rely on it for MITM protection or compliance.

**✅ 권장 방법: Android `network_security_config.xml`의 `<pin-set>` 사용**

```xml
<!-- android/app/src/main/res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <!-- expiration: 인증서 갱신 예상일 + 최소 1년으로 설정 권장 -->
        <pin-set expiration="2027-12-31">
            <pin digest="SHA-256">base64EncodedSPKIFingerprint=</pin>
            <pin digest="SHA-256">backupBase64EncodedSPKIFingerprint=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Requirements:**
- TLS 1.2+ only (server-side configuration; see `references/network-security.md § TLS Configuration`)
- `minSdk 21+` to ensure device supports TLS 1.2
- Certificate pinning for authentication endpoints
- Network security config for Android

See: `references/network-security.md` for complete configuration.

### 4. Source Code Protection

Protect your compiled application from reverse engineering:

```bash
# Build with obfuscation
flutter build apk --release \
  --obfuscate \
  --split-debug-info=build/debug-info
```

**build.gradle Configuration:**
```groovy
buildTypes {
    release {
        minifyEnabled true
        shrinkResources true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
    }
}
```

See: `references/code-protection.md` for obfuscation and ProGuard setup.

### 5. Platform Security

Detect compromised devices and secure platform interactions:

```dart
// Root/Jailbreak Detection
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

final isCompromised = await FlutterJailbreakDetection.jailbroken;
if (isCompromised) {
  // Handle compromised device
}
```

**Intent Security:**
- Use explicit intents with component names
- Validate all incoming intent data
- Use secure alternatives for internal broadcasts (LocalBroadcastManager is deprecated)

See: `references/platform-security.md` for platform-specific security.

## Security Audit Workflow

When auditing a Flutter app for security issues:

1. **Review AndroidManifest.xml**
   - Verify backup and debug settings
   - Check exported components
   - Audit permissions

2. **Inspect Data Storage Code**
   - Search for SharedPreferences usage with sensitive data
   - Verify encryption for local databases
   - Check file permission settings

3. **Validate Network Security**
   - Confirm HTTPS-only communication
   - Check for certificate pinning
   - Review network security config

4. **Verify Build Configuration**
   - Confirm obfuscation is enabled
   - Check ProGuard/R8 configuration
   - Verify debug logs are stripped

## Common Vulnerabilities

### High Severity
- **Hardcoded API Keys/Secrets**: Use secure storage (`flutter_secure_storage`); never use .env files for secrets (see code-protection.md)
- **Disabled SSL Verification**: Never use `badCertificateCallback` returning `true`
- **allowBackup="true"**: Data can be extracted via ADB backup
- **Cleartext Traffic**: Always use HTTPS

### Medium Severity
- **Excessive Permissions**: Request only necessary permissions
- **Unprotected Exported Components**: Add permission requirements
- **Debug Logs in Release**: Use `kDebugMode` or `kReleaseMode` guards

### Low Severity
- **Missing Root Detection**: Implement for sensitive applications
- **Verbose Error Messages**: Sanitize user-facing errors

## Resources

### Reference Documentation
- `references/android-manifest-security.md` - AndroidManifest.xml configuration
- `references/data-storage-security.md` - Secure data storage patterns
- `references/network-security.md` - Network security implementation
- `references/code-protection.md` - Obfuscation and code protection
- `references/platform-security.md` - Platform-specific security

## Recommended Packages

| Purpose | Package | Notes |
|---------|---------|-------|
| Secure Storage | `flutter_secure_storage` | Keychain/EncryptedSharedPreferences |
| Database Encryption | `sqlcipher_flutter_libs` | SQLite encryption |
| Root Detection | `flutter_jailbreak_detection` | Detect compromised devices |
| Certificate Pinning | `network_security_config.xml` | Android native pinning (recommended) |
| Environment Config | `flutter_dotenv` | ⚠️ Public config only! Never store secrets |

## Update Policy

이 문서의 빌드 환경 및 SDK 요구사항 정보는 시간이 지남에 따라 변경될 수 있습니다.

**Source of Truth (최신 정보 참조처):**
- **Flutter 빌드 요구사항**: [Flutter Release Notes](https://docs.flutter.dev/release/release-notes)
- **AGP/Gradle/JDK 호환성**: [Android AGP Compatibility Matrix](https://developer.android.com/build/releases/gradle-plugin#updating-gradle)
- **Google Play targetSdk 정책**: [Target API level requirements](https://developer.android.com/google/play/requirements/target-sdk)
- **AGP 마이그레이션**: [Flutter AGP Migration Guide](https://docs.flutter.dev/release/breaking-changes/migrate-to-agp-9)

> **📅 Last reviewed**: 2026-01-25
> 빌드 관련 버전 정보는 참조용이며, 반드시 위 공식 문서를 확인하세요.

## External References

- [KISA Mobile Application Security Guide](https://www.kisa.or.kr)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Flutter Security Documentation](https://docs.flutter.dev/security)
