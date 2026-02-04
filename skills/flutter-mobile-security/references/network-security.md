# Network Security

This document covers secure network communication practices for Flutter Android applications.

**Note:** 이 문서는 Android 전용입니다. (This document is Android-only.)

## Core Principles

1. **Always use HTTPS** - Never transmit sensitive data over HTTP
2. **Validate certificates** - Don't disable SSL/TLS verification
3. **Implement certificate pinning** - For high-security applications
4. **Configure network security** - Use Android's network security config

## HTTPS Enforcement

### Cleartext Traffic 기본 동작

> **중요: targetSdk에 따른 기본 동작 차이**
>
> | targetSdk | 기본값 | HTTP 허용 여부 |
> |-----------|--------|---------------|
> | 28+ (Android 9+) | `false` | 차단됨 |
> | 27 이하 | `true` | 허용됨 (취약) |
>
> `targetSdk 27` 이하인 레거시 프로젝트는 `usesCleartextTraffic`을 명시적으로 `false`로 설정하지 않으면
> HTTP 트래픽이 기본 허용되어 MITM 공격에 취약합니다.
>
> **권장:** 모든 프로젝트에서 명시적으로 `usesCleartextTraffic="false"` 또는
> `network_security_config.xml`의 `cleartextTrafficPermitted="false"`를 설정하세요.

### Android Network Security Config

> **Note:** Network Security Config는 Android 7.0 (API 24) 이상에서만 지원됩니다.
> `minSdk < 24`인 경우, 해당 기기에서는 이 설정이 무시되며 시스템 기본 동작을 따릅니다.
> 하위 호환이 필요하면 네이티브 네트워크 스택 레벨의 핀닝(OkHttp `CertificatePinner` 등)을 고려하세요.

Create `android/app/src/main/res/xml/network_security_config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Block all cleartext (HTTP) traffic -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>

    <!-- Optional: Allow specific domains for development -->
    <!-- Remove in production! -->
    <!--
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">10.0.2.2</domain>
    </domain-config>
    -->
</network-security-config>
```

#### Debug Overrides (개발 환경 전용)

디버그 빌드에서만 사용자 설치 CA(예: Charles Proxy, mitmproxy)를 허용하려면 `<debug-overrides>`를 사용합니다:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>

    <!-- 디버그 빌드에서만 사용자 설치 CA 신뢰 (프록시 디버깅용) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

> **주의:** `<debug-overrides>`는 `debuggable=true`인 빌드에서만 적용됩니다.
> 릴리스 빌드에서는 자동으로 무시되므로 프로덕션 보안에 영향을 주지 않습니다.

Reference in `AndroidManifest.xml`:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

## Certificate Pinning

Certificate pinning prevents man-in-the-middle attacks by validating that the server's certificate matches an expected value.

---

### ⚠️ 중요: `badCertificateCallback`의 한계 (Important: Limitations of `badCertificateCallback`)

> **경고 (Warning): Dart의 `badCertificateCallback`은 실제 Certificate Pinning을 구현하지 못합니다!**
> (Dart's `badCertificateCallback` cannot implement real Certificate Pinning!)
>
> `badCertificateCallback`은 시스템이 인증서를 **"거부"**할 때만 호출됩니다.
> (`badCertificateCallback` is only called when the system **"rejects"** a certificate.)
>
> **문제점 (Problems):**
> - Let's Encrypt, DigiCert, Comodo 등 신뢰할 수 있는 CA에서 발급된 인증서는 시스템이 자동으로 신뢰합니다
>   (Certificates from trusted CAs like Let's Encrypt, DigiCert, Comodo are automatically trusted by the system)
> - 이런 유효한 인증서에 대해서는 `badCertificateCallback`이 **호출되지 않습니다**
>   (For these valid certificates, `badCertificateCallback` is **NOT called**)
> - 따라서 공격자가 유효한 CA 인증서를 사용하면 Dart 코드의 핀닝을 우회할 수 있습니다
>   (Therefore, attackers with valid CA certificates can bypass Dart-based pinning)
>
> **결론 (Conclusion):** Dart 코드만으로는 진정한 Certificate Pinning을 구현할 수 없습니다.
> (True Certificate Pinning cannot be implemented with Dart code alone.)
>
> **Important:** Dart-only pinning is NOT considered real certificate pinning on Android.
> It does not trigger for valid CA certificates, so it cannot provide MITM protection or meet pinning compliance requirements.
> Use Android `network_security_config.xml` `<pin-set>` as the primary control. Dart-only logic may be used only for supplemental detection.

---

### ✅ 권장 방법: Android `network_security_config.xml` (Pin-Set)

Android에서 실제로 작동하는 Certificate Pinning은 `network_security_config.xml`의 `<pin-set>`을 사용해야 합니다.

**1. Pin 값 생성하기:**

```bash
# 서버 인증서의 SPKI (Subject Public Key Info) 해시 추출
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

**2. `android/app/src/main/res/xml/network_security_config.xml` 생성:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- 기본 설정: HTTP 차단 -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>

    <!-- Certificate Pinning 적용할 도메인 -->
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <!-- UPDATE THIS DATE: Set to ~1 year after your certificate's expected renewal -->
        <pin-set expiration="2027-12-31">
            <!-- 기본 핀 (현재 인증서) -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- 백업 핀 (인증서 갱신 대비) -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**3. `AndroidManifest.xml`에서 참조:**

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

**주의사항:**
- 반드시 백업 핀을 포함하세요 (인증서 갱신 시 앱이 동작하지 않을 수 있음)
- `expiration` 날짜를 설정하여 핀 만료 시 폴백할 수 있도록 하세요
- 인증서 갱신 일정을 관리하고 미리 새 핀을 배포하세요
- **Important:** Update the expiration date in your actual implementation (the example uses `2027-12-31` as a placeholder)

---

### ❌ Incorrect Example: Dart Code (For Educational Purposes Only)

> **🚫 DO NOT COPY THIS CODE FOR CERTIFICATE PINNING!**
>
> The code below demonstrates an **incorrect approach**. It is included for educational purposes only.
> `badCertificateCallback` is NOT called for valid CA certificates, so
> this code alone provides **NO actual Certificate Pinning protection**.
>
> **You MUST use `network_security_config.xml` as shown above!**

The code below can only be used as a **supplementary defense layer**. It does NOT work as standalone Certificate Pinning.

```dart
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';

class SecureHttpClient {
  // SHA-256 fingerprint of your server's certificate
  // Get it using: openssl s_client -connect api.example.com:443 | openssl x509 -fingerprint -sha256
  static const String _certificateFingerprint =
      'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';

  late final Dio _dio;

  SecureHttpClient() {
    _dio = Dio(BaseOptions(
      baseUrl: 'https://api.example.com',
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
    ));

    _configureCertificatePinning();
  }

  void _configureCertificatePinning() {
    (_dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
      final client = HttpClient();

      // ⚠️ 주의: 이 콜백은 시스템이 인증서를 "거부"할 때만 호출됩니다!
      // 유효한 CA 인증서에 대해서는 호출되지 않으므로,
      // 실제 핀닝 효과가 없습니다. network_security_config.xml을 사용하세요.
      client.badCertificateCallback = (X509Certificate cert, String host, int port) {
        // Convert certificate to SHA-256 fingerprint
        final fingerprint = _getCertificateFingerprint(cert);

        // Verify against pinned certificate
        if (fingerprint == _certificateFingerprint.replaceAll(':', '').toLowerCase()) {
          return true;  // Certificate matches
        }

        // ⚠️ Never log certificate details in production!
        // Logging removed - use proper logging framework with kDebugMode guard if needed

        return false;  // Reject connection
      };

      return client;
    };
  }

  String _getCertificateFingerprint(X509Certificate cert) {
    // The sha256 property returns the SHA-256 hash of the certificate
    return cert.sha256.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Future<Response> get(String path) => _dio.get(path);
  Future<Response> post(String path, {dynamic data}) => _dio.post(path, data: data);
}
```

## TLS Configuration

### Platform TLS Behavior

> **Note:** `network_security_config.xml` controls certificate trust and cleartext traffic, but **does not directly enforce TLS version minimum**.
>
> TLS version is determined by:
> 1. **Server-side configuration** (server must require TLS 1.2+)
> 2. **Platform defaults** (Android API 29+ defaults to TLS 1.3, older versions support TLS 1.2)
>
> To ensure TLS 1.2+ usage:
> - Configure your server to reject TLS 1.0/1.1 connections
> - Set `minSdk 21` or higher (TLS 1.2 supported on API 21+)
> - Android API 29+ enables TLS 1.3 by default

## Secure API Communication

### Request/Response Validation

```dart
class SecureApiClient {
  final Dio _dio;

  SecureApiClient(this._dio) {
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) {
        // Ensure HTTPS
        if (options.uri.scheme != 'https') {
          return handler.reject(
            DioException(
              requestOptions: options,
              error: 'HTTPS required',
            ),
          );
        }

        return handler.next(options);
      },
      onResponse: (response, handler) {
        // Validate response
        _validateResponse(response);
        return handler.next(response);
      },
      onError: (error, handler) {
        // Don't expose sensitive error details
        if (error.response?.statusCode == 401) {
          // Handle authentication error
        }
        return handler.next(error);
      },
    ));
  }

  void _validateResponse(Response response) {
    // Add response validation logic
  }
}
```

### Secure Token Handling

```dart
class AuthInterceptor extends Interceptor {
  final FlutterSecureStorage _storage;

  AuthInterceptor(this._storage);

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) async {
    // Get token from secure storage
    final token = await _storage.read(key: 'auth_token');

    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }

    handler.next(options);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    if (err.response?.statusCode == 401) {
      // Token expired, clear and redirect to login
      await _storage.delete(key: 'auth_token');
      // Navigate to login screen
    }

    handler.next(err);
  }
}
```

## WebSocket Security

```dart
import 'package:web_socket_channel/web_socket_channel.dart';

class SecureWebSocketClient {
  WebSocketChannel? _channel;

  Future<void> connect(String url) async {
    // Ensure WSS (WebSocket Secure)
    if (!url.startsWith('wss://')) {
      throw SecurityException('WSS required for WebSocket connections');
    }

    _channel = WebSocketChannel.connect(
      Uri.parse(url),
    );
  }
}
```

## Common Vulnerabilities to Avoid

### 1. Disabling Certificate Verification

```dart
// NEVER DO THIS IN PRODUCTION!
client.badCertificateCallback = (cert, host, port) => true;  // INSECURE!
```

### 2. Allowing Cleartext Traffic

```xml
<!-- NEVER DO THIS IN PRODUCTION! -->
<application android:usesCleartextTraffic="true">  <!-- INSECURE! -->
```

### 3. Hardcoded API Keys in URLs

```dart
// BAD: API key in URL
final url = 'https://api.example.com?api_key=SECRET123';  // INSECURE!

// GOOD: API key in header, loaded from secure storage
final apiKey = await secureStorage.read(key: 'api_key');
dio.options.headers['X-API-Key'] = apiKey;
```

## Best Practices Summary

1. **Always use HTTPS** - Configure network security to block HTTP
2. **Implement certificate pinning** - For sensitive API endpoints
3. **Use TLS 1.2+** - Disable older, insecure protocols
4. **Validate all responses** - Don't trust server data blindly
5. **Secure token storage** - Use flutter_secure_storage for tokens
6. **Handle errors securely** - Don't expose sensitive information in errors
7. **Test security** - Regularly test with proxy tools

위의 `network_security_config.xml` 예시와 Dart 코드 패턴을 참조하여 앱의 네트워크 보안을 구성하세요.
