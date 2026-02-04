# AndroidManifest.xml Security Configuration

This document provides detailed guidance on securing your Flutter app's AndroidManifest.xml configuration.

## Location

```
android/app/src/main/AndroidManifest.xml
```

## Critical Security Attributes

### 1. Application-Level Settings

```xml
<application
    android:allowBackup="false"
    android:debuggable="false"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

#### android:allowBackup

**Recommended:** `false`

When `true`, app data can be extracted using ADB backup:
```bash
# Attacker can extract data with:
adb backup -apk com.example.app
```

This exposes SharedPreferences, databases, and internal files.

**Exception:** If backup is required, use `android:fullBackupContent` to exclude sensitive files:
```xml
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules">
```

backup_rules.xml:
```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="sharedpref" path="secret_prefs.xml"/>
    <exclude domain="database" path="sensitive.db"/>
</full-backup-content>
```

#### Android 12+ (API 31+): dataExtractionRules

Android 12 이상에서는 `fullBackupContent` 대신 `dataExtractionRules`가 권장됩니다:

```xml
<application
    android:allowBackup="true"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules">
```

data_extraction_rules.xml:
```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="secret_prefs.xml"/>
        <exclude domain="database" path="sensitive.db"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="secret_prefs.xml"/>
        <exclude domain="database" path="sensitive.db"/>
    </device-transfer>
</data-extraction-rules>
```

> **⚠️ 주의:** targetSdk 31+ (Android 12+)에서 `allowBackup="false"`는 일부 제조사 기기에서 디바이스 간 전송(device-to-device transfer)을
> 완전히 차단하지 않을 수 있습니다. 민감한 데이터는 `dataExtractionRules`의 `<device-transfer>` 섹션에서도
> 명시적으로 제외하세요.

#### android:debuggable

**Recommended:** `false` for release builds

Flutter automatically sets this based on build type, but verify in release APK:

**Unix/macOS/Git Bash:**
```bash
# Check if debuggable
aapt dump badging app-release.apk | grep debuggable
```

**Windows (PowerShell):**
```powershell
aapt dump badging app-release.apk | Select-String "debuggable"
```

**Windows (CMD):**
```cmd
aapt dump badging app-release.apk | findstr "debuggable"
```

When `debuggable="true"`:
- Debuggers can attach to the process
- Memory can be inspected and modified
- App logic can be manipulated at runtime

#### android:usesCleartextTraffic

**Recommended:** `false`

Prevents unencrypted HTTP traffic. Enforces HTTPS for all connections.

**기본 동작 (Default Behavior):**
- `targetSdk 28+` (Android 9+): 기본값이 `false` — HTTP 차단됨
- `targetSdk 27 이하`: 기본값이 `true` — HTTP 허용됨 (보안 취약)

> **주의:** `targetSdk`가 27 이하인 레거시 프로젝트는 명시적으로 `false`를 설정하지 않으면 HTTP 트래픽이 허용됩니다.

명시적으로 `false`를 설정하여 의도를 명확히 하세요.

### 2. Component Export Settings

All components (activities, services, receivers, providers) must explicitly declare `android:exported`:

```xml
<!-- Main launcher activity - must be exported -->
<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>

<!-- Internal activity - should NOT be exported -->
<activity
    android:name=".SettingsActivity"
    android:exported="false"/>

<!-- Service handling sensitive operations -->
<service
    android:name=".AuthService"
    android:exported="false"/>

<!-- Broadcast receiver -->
<receiver
    android:name=".NotificationReceiver"
    android:exported="false">
    <intent-filter>
        <action android:name="com.example.INTERNAL_ACTION"/>
    </intent-filter>
</receiver>
```

#### Rules for android:exported

| Component Type | Has Intent Filter | Recommended exported |
|---------------|-------------------|---------------------|
| Launcher Activity | Yes (MAIN/LAUNCHER) | `true` |
| Deep Link Activity | Yes | `true` (with validation) |
| Internal Activity | No | `false` |
| Background Service | No | `false` |
| Internal Receiver | Internal actions | `false` |
| System Receiver | System actions | `true` (required) |

### 3. Permission Requirements

#### Minimize Permissions

Only request permissions that are absolutely necessary:

```xml
<!-- BAD: Requesting unnecessary permissions -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.CAMERA"/>

<!-- GOOD: Only what's needed -->
<uses-permission android:name="android.permission.INTERNET"/>
```

#### Protect Exported Components

For components that must be exported, require permissions:

```xml
<!-- Define custom permission -->
<permission
    android:name="com.example.app.ADMIN_ACCESS"
    android:protectionLevel="signature"/>

<!-- Require permission to access -->
<activity
    android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.example.app.ADMIN_ACCESS"/>
```

Protection levels:
- `normal` - Granted automatically
- `dangerous` - Requires user approval
- `signature` - Only apps signed with same key
- `signatureOrSystem` - Same key or system apps

### 4. Intent Filter Security

#### Validate Deep Links

```xml
<activity
    android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="https"
            android:host="example.com"
            android:pathPrefix="/app"/>
    </intent-filter>
</activity>
```

**Always validate intent data in code:**
```dart
// In your Flutter code or platform channel
final uri = Uri.parse(intentData);
if (uri.host != 'example.com') {
  throw SecurityException('Invalid deep link host');
}
```

### 5. Provider Security

```xml
<provider
    android:name=".SecureProvider"
    android:authorities="com.example.app.provider"
    android:exported="false"
    android:grantUriPermissions="false">
</provider>
```

If the provider must be exported:
```xml
<provider
    android:name=".SharedProvider"
    android:authorities="com.example.app.shared"
    android:exported="true"
    android:readPermission="com.example.app.READ_DATA"
    android:writePermission="com.example.app.WRITE_DATA">
</provider>
```

## Security Audit Commands

> **Prerequisites:** Android SDK의 `build-tools`가 PATH에 있어야 합니다.
> 예: `C:\Users\<username>\AppData\Local\Android\Sdk\build-tools\34.0.0`

### Check Current Settings

**Unix/macOS/Git Bash:**
```bash
# Extract and view AndroidManifest.xml from APK
aapt dump xmltree app-release.apk AndroidManifest.xml

# Check specific attributes
aapt dump badging app-release.apk | grep -E "allowBackup|debuggable"

# List all exported components
aapt dump xmltree app-release.apk AndroidManifest.xml | grep -B5 'exported.*true'
```

**Windows (PowerShell):**
```powershell
# Extract and view AndroidManifest.xml from APK
aapt dump xmltree app-release.apk AndroidManifest.xml

# Check specific attributes
aapt dump badging app-release.apk | Select-String "allowBackup|debuggable"

# List all exported components (requires manual review of output)
aapt dump xmltree app-release.apk AndroidManifest.xml | Select-String -Context 5,0 'exported.*true'
```

**Windows (CMD):**
```cmd
:: Extract and view AndroidManifest.xml from APK
aapt dump xmltree app-release.apk AndroidManifest.xml

:: Check specific attributes
aapt dump badging app-release.apk | findstr "allowBackup debuggable"
```

### Verify in Flutter Project

**Unix/macOS/Git Bash:**
```bash
# Search for security-related settings
grep -r "allowBackup\|debuggable\|exported\|usesCleartextTraffic" android/
```

**Windows (PowerShell):**
```powershell
# Search for security-related settings
Get-ChildItem -Path android -Recurse -Include *.xml,*.gradle | Select-String "allowBackup|debuggable|exported|usesCleartextTraffic"
```

**Windows (CMD):**
```cmd
:: Search for security-related settings
findstr /s "allowBackup debuggable exported usesCleartextTraffic" android\*.xml android\*.gradle
```

## Common Mistakes

### 1. Missing exported Attribute (Android 12+)

Error: `Manifest merger failed: android:exported needs to be explicitly specified`

Fix: Add `android:exported` to all components with intent filters.

### 2. allowBackup Left as Default

The default is `true`. Always explicitly set to `false`:
```xml
android:allowBackup="false"
```

### 3. Overly Permissive Exports

```xml
<!-- BAD: Everything exported -->
<activity android:name=".SensitiveActivity" android:exported="true"/>

<!-- GOOD: Protected export -->
<activity
    android:name=".SensitiveActivity"
    android:exported="true"
    android:permission="com.example.INTERNAL"/>
```

## Complete Secure Template

아래는 보안 설정이 적용된 AndroidManifest.xml 템플릿입니다:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <!-- 최소한의 권한만 요청 -->
    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher">

        <!-- 메인 액티비티 - 런처이므로 exported=true 필수 -->
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTop">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <!-- 내부 액티비티는 exported=false -->
        <!-- <activity android:name=".InternalActivity" android:exported="false"/> -->

    </application>
</manifest>
```
