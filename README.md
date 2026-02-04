# TDD Flutter Security Plugin

TDD(Test-Driven Development) 방법론과 KISA 모바일 보안 가이드라인을 결합한 Flutter Android 앱 개발 플러그인입니다.

## Overview

이 플러그인은 두 가지 핵심 기능을 제공합니다:

1. **TDD Flutter Security Architect Agent**: 보안 요구사항을 테스트로 먼저 작성하고, 테스트를 통과하는 보안 코드를 구현하는 TDD 방식의 개발 지원
2. **Flutter Android Security Skill**: KISA 가이드 기반의 포괄적인 Flutter Android 보안 가이드

## Features

### Agent: tdd-flutter-security-architect

- 보안 기능을 TDD 방식으로 개발
- 민감한 데이터 처리 기능 구현 시 보안 테스트 우선 작성
- 보안 요구사항 분석 및 체크리스트 생성
- Red-Green-Refactor 사이클에서 보안 검증

**사용 예시:**
- "인증 기능을 보안을 고려해서 TDD로 구현해 줘"
- "flutter_secure_storage를 사용한 토큰 저장을 테스트와 함께 구현해 줘"
- "네트워크 통신에 certificate pinning을 TDD로 적용해 줘"
- "앱 보안 점검하고 테스트 코드 작성해 줘"

### Skill: Flutter Android Security

KISA 모바일 보안 가이드 기반의 5개 보안 도메인:

1. **AndroidManifest.xml 보안**: allowBackup, debuggable, exported 설정
2. **데이터 저장소 보안**: flutter_secure_storage, SQLCipher
3. **네트워크 보안**: HTTPS, certificate pinning (network_security_config.xml)
4. **코드 보호**: 난독화, ProGuard/R8, 로그 제거
5. **플랫폼 보안**: 루팅 탐지, Intent 검증, 스크린 캡처 보호

## Installation

플러그인을 설치하려면:

```bash
/plugin marketplace add https://github.com/LinaYoun/tdd-flutter-security.git
```



## Usage

### TDD 보안 개발 워크플로우

1. **보안 요구사항 분석**: 기능의 보안 영향 분석
2. **보안 테스트 작성**: 테스트 먼저 작성 (Red)
3. **보안 구현**: 테스트 통과하는 최소 코드 작성 (Green)
4. **리팩토링**: 코드 정리하며 보안 유지 (Refactor)
5. **보안 감사**: 최종 체크리스트 검증

### 보안 체크리스트 (릴리스 전)

- [ ] 하드코딩된 비밀 없음
- [ ] 민감한 데이터는 암호화 저장소 사용
- [ ] 네트워크 호출은 HTTPS + 적절한 검증
- [ ] AndroidManifest.xml 보안 설정 적용
- [ ] 릴리스 빌드에서 디버그 로그 제거
- [ ] ProGuard/R8 난독화 설정

## Directory Structure

```
tdd-flutter-security/
├── .claude-plugin/
│   └── plugin.json           # 플러그인 매니페스트
├── agents/
│   └── tdd-flutter-security-architect.md  # TDD 보안 에이전트
├── skills/
│   └── flutter-mobile-security/
│       ├── SKILL.md          # 메인 보안 스킬
│       └── references/
│           ├── android-manifest-security.md
│           ├── data-storage-security.md
│           ├── network-security.md
│           ├── code-protection.md
│           └── platform-security.md
└── README.md
```

## Security Resources

- [KISA 모바일 앱 보안 가이드](https://www.kisa.or.kr)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Flutter Security Documentation](https://docs.flutter.dev/security)

## Version History

- **v1.0.0**: Initial release
  - TDD Flutter Security Architect agent
  - Flutter Android Security skill (from flutter-security v1.1.0)

## License

This plugin is provided for educational and development purposes.

---

**Note:** 이 플러그인은 Android 전용입니다. iOS 보안 가이드는 별도로 제공됩니다.
