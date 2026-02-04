# Platform Security

This document covers platform-specific security measures for Flutter Android applications.

**Note:** 이 문서는 Android 전용입니다. (This document is Android-only.)

## Root/Jailbreak Detection

### Why Detect Compromised Devices

Rooted/jailbroken devices have:
- Elevated privileges that bypass security controls
- Potential for malicious apps to intercept data
- Ability to modify app behavior and memory
- Access to app's private storage

### Using flutter_jailbreak_detection

> **📦 Version Note**: 아래 버전은 참조용 예시입니다. 최신 안정 버전은 [pub.dev](https://pub.dev)에서 확인하세요.

```yaml
dependencies:
  flutter_jailbreak_detection: ^1.10.0
```

```dart
import 'package:flutter/material.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

/// Security status with separate risk levels for root/jailbreak vs developer mode.
///
/// Policy Note:
/// - isRooted (jailbroken) = HIGH RISK: Should restrict sensitive features
/// - isDeveloperMode = MEDIUM RISK: May be legitimate development, show WARNING only
///
/// Treating developerMode the same as root causes false positives for developers
/// and testers. Apps should choose appropriate policies based on their security requirements.
class DeviceSecurityStatus {
  final bool? isRooted;       // null = detection failed
  final bool? isDeveloperMode;

  DeviceSecurityStatus({this.isRooted, this.isDeveloperMode});

  /// High risk: rooted/jailbroken device - should block sensitive features
  bool get isHighRisk => isRooted == true;

  /// Medium risk: developer mode enabled (may be legitimate development)
  bool get isMediumRisk => isDeveloperMode == true && isRooted != true;

  /// Device has any security concern (for logging/analytics)
  bool get hasSecurityConcern => isHighRisk || isMediumRisk;
}

class DeviceSecurityService {
  /// Returns detailed security status instead of single boolean.
  /// This allows apps to respond appropriately to different risk levels.
  Future<DeviceSecurityStatus> checkDeviceSecurity() async {
    try {
      final jailbroken = await FlutterJailbreakDetection.jailbroken;
      final developerMode = await FlutterJailbreakDetection.developerMode;

      return DeviceSecurityStatus(
        isRooted: jailbroken,
        isDeveloperMode: developerMode,
      );
    } catch (e) {
      // If detection fails, report unknown status
      return DeviceSecurityStatus(isRooted: null, isDeveloperMode: null);
    }
  }

  /// Convenience method: returns true if device has any security concern.
  Future<bool> isDeviceCompromised() async {
    final status = await checkDeviceSecurity();
    return status.hasSecurityConcern;
  }

  Future<void> checkDeviceAndProceed(BuildContext context) async {
    final status = await checkDeviceSecurity();

    if (status.isHighRisk) {
      _showSecurityWarning(context, isHighRisk: true);
    } else if (status.isMediumRisk) {
      _showSecurityWarning(context, isHighRisk: false);
    }
  }

  void _showSecurityWarning(BuildContext context, {required bool isHighRisk}) {
    final title = isHighRisk ? 'Security Warning' : 'Developer Mode Detected';
    final message = isHighRisk
        ? 'This device appears to be rooted/jailbroken. '
          'For your security, some features may be restricted.'
        : 'Developer mode is enabled on this device. '
          'This is normal for development but may indicate elevated risk.';

    showDialog(
      context: context,
      barrierDismissible: !isHighRisk,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('I Understand'),
          ),
        ],
      ),
    );
  }
}
```

### Response Strategies

When a compromised device is detected:

1. **Warning Only** - Notify user but allow continued use
2. **Feature Restriction** - Disable sensitive features
3. **Block Usage** - Prevent app from running entirely

```dart
enum SecurityPolicy {
  warn,
  restrict,
  block,
}

class SecurityManager {
  final SecurityPolicy policy;

  SecurityManager({this.policy = SecurityPolicy.warn});

  Future<bool> canProceed() async {
    final compromised = await DeviceSecurityService().isDeviceCompromised();

    if (!compromised) return true;

    switch (policy) {
      case SecurityPolicy.warn:
        // Show warning, allow proceed
        return true;
      case SecurityPolicy.restrict:
        // Allow basic features only
        return true;
      case SecurityPolicy.block:
        // Block entirely
        return false;
    }
  }
}
```

## 선택적 강화: 서버 측 검증 (Optional Hardening: Server-Side Verification)

> **대상:** 금융, 결제, 의료 등 고위험 앱

클라이언트 측 루팅 탐지는 우회될 수 있습니다. 고위험 앱은 **Play Integrity API**를 통한
서버 측 검증을 고려하세요.

### Play Integrity API

Google Play Integrity API는 다음을 검증합니다:
- 앱이 변조되지 않았는지 (App Integrity)
- 기기가 신뢰할 수 있는 Android 환경인지 (Device Integrity)
- Google Play 라이선스 상태 (Account Licensing)

**구현 흐름:**
1. 클라이언트: Play Integrity API로 토큰 생성
2. 서버: 토큰을 Google 서버에 전송하여 검증
3. 서버: 검증 결과에 따라 민감한 기능 허용/차단

**참고 자료:**
- [Play Integrity API 개요](https://developer.android.com/google/play/integrity/overview)
- [Play Integrity API 설정 가이드](https://developer.android.com/google/play/integrity/setup)

```dart
// 클라이언트 측 예시 (play_integrity 패키지 사용)
import 'package:play_integrity/play_integrity.dart';

class IntegrityService {
  Future<String?> getIntegrityToken(String serverGeneratedNonce) async {
    try {
      // nonce는 서버에서 생성해야 함
      final token = await PlayIntegrity.requestIntegrityToken(
        cloudProjectNumber: 'YOUR_CLOUD_PROJECT_NUMBER',
        nonce: serverGeneratedNonce,
      );
      return token;
    } catch (e) {
      return null;
    }
  }
}
```

> **Note:** Play Integrity API 토큰은 반드시 **서버에서 검증**해야 합니다.
> 클라이언트에서 결과를 해석하면 우회 가능합니다.

## Intent Security (Android)

### Explicit vs Implicit Intents

**Implicit intents** can be intercepted by malicious apps. Use **explicit intents** when possible.

```kotlin
// BAD: Implicit intent - can be intercepted
val intent = Intent("com.example.ACTION_PROCESS_DATA")
intent.putExtra("sensitive_data", userData)
startActivity(intent)

// GOOD: Explicit intent - specific target
val intent = Intent(this, DataProcessorActivity::class.java)
intent.putExtra("sensitive_data", userData)
startActivity(intent)
```

### Validating Incoming Intents

```kotlin
class DeepLinkActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        intent?.data?.let { uri ->
            // Validate the incoming URI
            if (!isValidDeepLink(uri)) {
                finish()
                return
            }
        }
    }

    private fun isValidDeepLink(uri: Uri): Boolean {
        // Verify scheme
        if (uri.scheme != "https" && uri.scheme != "myapp") {
            return false
        }

        // Verify host
        val allowedHosts = listOf("example.com", "www.example.com")
        if (uri.host !in allowedHosts) {
            return false
        }

        // Verify path doesn't contain injection attempts
        val path = uri.path ?: ""
        if (path.contains("..") || path.contains("<") || path.contains(">")) {
            return false
        }

        return true
    }
}
```

### 내부 브로드캐스트 보안 (Internal Broadcast Security)

외부 앱이 브로드캐스트를 가로채지 못하도록 해야 합니다:
(Prevent external apps from intercepting broadcasts:)

```kotlin
// BAD: 시스템 브로드캐스트 - 외부 앱이 가로챌 수 있음
// (System broadcast - can be intercepted by external apps)
sendBroadcast(Intent("com.example.USER_LOGGED_IN"))

// LocalBroadcastManager는 deprecated됨 - 사용하지 마세요!
// (LocalBroadcastManager is deprecated - do not use!)
// LocalBroadcastManager.getInstance(this).sendBroadcast(...)
```

**권장 대안 (Recommended Alternatives)** (LocalBroadcastManager 대신 사용 / Use instead of LocalBroadcastManager):
- **LiveData**: 생명주기 인식 업데이트 (Lifecycle-aware updates)
- **EventBus**: 이벤트 기반 아키텍처 (Event-driven architecture)
- **Kotlin Flows**: 반응형 스트림 (Reactive streams)

```dart
// Flutter alternative: Use providers or streams
class AuthEventNotifier extends ChangeNotifier {
  bool _isLoggedIn = false;

  bool get isLoggedIn => _isLoggedIn;

  void setLoggedIn(bool value) {
    _isLoggedIn = value;
    notifyListeners();
  }
}
```

## Screen Capture Protection

### Preventing Screenshots (Android)

```kotlin
// In MainActivity.kt
class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
```

### Flutter Implementation via Platform Channel

```dart
class ScreenSecurityService {
  static const _channel = MethodChannel('com.example.app/screen_security');

  static Future<void> enableSecureMode() async {
    await _channel.invokeMethod('enableSecureMode');
  }

  static Future<void> disableSecureMode() async {
    await _channel.invokeMethod('disableSecureMode');
  }
}

// Use when displaying sensitive information
class SensitiveScreen extends StatefulWidget {
  @override
  _SensitiveScreenState createState() => _SensitiveScreenState();
}

class _SensitiveScreenState extends State<SensitiveScreen> {
  @override
  void initState() {
    super.initState();
    ScreenSecurityService.enableSecureMode();
  }

  @override
  void dispose() {
    ScreenSecurityService.disableSecureMode();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Text('Sensitive Content'),
      ),
    );
  }
}
```

## Clipboard Security

### Clearing Sensitive Data from Clipboard

```dart
import 'package:flutter/services.dart';

class ClipboardSecurity {
  // Clear clipboard after copying sensitive data
  static Future<void> copyAndClear(String text, {Duration delay = const Duration(seconds: 30)}) async {
    await Clipboard.setData(ClipboardData(text: text));

    // Clear after delay
    Future.delayed(delay, () async {
      await Clipboard.setData(const ClipboardData(text: ''));
    });
  }

  // Copy with user notification
  static Future<void> copySecurely(BuildContext context, String text) async {
    await copyAndClear(text);

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Copied! Clipboard will be cleared in 30 seconds.'),
      ),
    );
  }
}
```

## Biometric Authentication

### Using local_auth Package

> **📦 Version Note**: 아래 버전은 참조용 예시입니다. 최신 안정 버전은 [pub.dev](https://pub.dev)에서 확인하세요.

```yaml
dependencies:
  local_auth: ^2.1.7
```

```dart
import 'package:local_auth/local_auth.dart';

class BiometricService {
  final _auth = LocalAuthentication();

  Future<bool> isBiometricAvailable() async {
    final canAuthenticateWithBiometrics = await _auth.canCheckBiometrics;
    final canAuthenticate = canAuthenticateWithBiometrics || await _auth.isDeviceSupported();
    return canAuthenticate;
  }

  Future<List<BiometricType>> getAvailableBiometrics() async {
    return await _auth.getAvailableBiometrics();
  }

  Future<bool> authenticate({String reason = 'Please authenticate'}) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: false,  // Allow PIN/pattern as fallback
        ),
      );
    } catch (e) {
      return false;
    }
  }
}
```

### Android Configuration

Add to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC"/>
```

## App Backgrounding Security

### Hiding Content When App Goes to Background

```dart
class SecureApp extends StatefulWidget {
  @override
  _SecureAppState createState() => _SecureAppState();
}

class _SecureAppState extends State<SecureApp> with WidgetsBindingObserver {
  bool _obscureContent = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    setState(() {
      _obscureContent = state == AppLifecycleState.paused ||
                        state == AppLifecycleState.inactive;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        MyApp(),
        if (_obscureContent)
          Container(
            color: Colors.white,
            child: Center(
              child: Image.asset('assets/logo.png'),
            ),
          ),
      ],
    );
  }
}
```

## Best Practices Summary

1. **Root/Jailbreak Detection**
   - Implement detection for sensitive apps
   - Choose appropriate response (warn/restrict/block)
   - Don't rely solely on client-side checks
   - **고위험 앱:** Play Integrity API로 서버 측 검증 고려

2. **Intent Security**
   - Use explicit intents when possible
   - Validate all incoming intent data
   - Use internal broadcast mechanisms

3. **Screen Protection**
   - Enable FLAG_SECURE for sensitive screens
   - Clear clipboard after copying sensitive data

4. **Biometric Authentication**
   - Use for additional security layer
   - Always provide fallback authentication

5. **Background Protection**
   - Obscure sensitive content when backgrounded
   - Implement session timeout

6. **Defense in Depth**
   - Combine multiple security measures
   - Don't rely on any single protection

## External Resources

- [Android Security Guidelines](https://developer.android.com/topic/security)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
