
# Advanced WordPress Plugin Security Scanner

WordPress 플러그인의 보안 취약점을 자동으로 탐지하는 고급 보안 스캐너입니다.

## 주요 기능

- **자동 취약점 탐지**: XSS, SQL Injection, LFI, RCE 등 9가지 주요 취약점 패턴 탐지
- **멀티스레드 스캔**: 빠른 분석을 위한 병렬 처리
- **신뢰도 평가**: AI 기반 False Positive 감소 시스템
- **상세 리포트**: JSON 및 HTML 형식의 자동 보고서 생성
- **플러그인 메타데이터**: WordPress.org에서 플러그인 정보 자동 수집

## 시스템 요구사항

- Python 3.7 이상
- 필요한 패키지:
  ```
  pip install requests beautifulsoup4
  ```

## 설치 방법

1. 프로젝트 디렉토리 생성
```bash
mkdir C:\Tools\Wordpress-Plugin-Scanner
cd C:\Tools\Wordpress-Plugin-Scanner
```

2. 스캐너 스크립트 저장
- `advanced_scanner.py` 파일로 저장

3. 필요한 패키지 설치
```
pip install requests beautifulsoup4
```

## 사용 방법

### 1. 플러그인 준비

분석할 WordPress 플러그인 ZIP 파일을 `downloads` 폴더에 넣습니다:

```
C:\Tools\Wordpress-Plugin-Scanner\
└── downloads\
    ├── plugin1.zip
    ├── plugin2.zip
    └── plugin3.zip
```

### 2. 스캐너 실행

```
python advanced_scanner.py
```

### 3. 스캔 프로세스

스캐너는 다음 단계를 자동으로 수행합니다:

1. **ZIP 압축 해제**: downloads 폴더의 모든 ZIP 파일 자동 압축 해제
2. **코드 스캔**: 모든 PHP 파일에서 취약점 패턴 탐지
3. **결과 분석**: 취약점 심각도 및 신뢰도 평가
4. **보고서 생성**: JSON 및 HTML 형식의 상세 보고서 생성

## 탐지 가능한 취약점 유형

| 취약점 | 심각도 | 설명 |
|--------|--------|------|
| SQL Injection | CRITICAL | 사용자 입력이 SQL 쿼리에 직접 사용됨 |
| File Inclusion | CRITICAL | 사용자가 제어 가능한 파일 경로 |
| Command Injection | CRITICAL | 사용자 입력으로 시스템 명령 실행 |
| XSS (Direct Output) | HIGH | 입력값 sanitization 없이 직접 출력 |
| XSS (Printf) | HIGH | printf 함수에서 비정제 입력 사용 |
| Path Traversal | HIGH | 사용자 제어 경로로 파일 작업 |
| CSRF Missing | MEDIUM | Nonce 검증 누락 |
| Unvalidated Redirect | MEDIUM | 검증되지 않은 리다이렉트 |
| Information Disclosure | LOW | 디버그 함수를 통한 정보 노출 |

## 출력 파일

스캔 완료 후 `security_results` 폴더에 다음 파일이 생성됩니다:

### JSON 보고서
```
security_results/security_report_20251013_143022.json
```

다음 정보를 포함:
- 스캔 타임스탬프
- 전체 플러그인 수
- 총 취약점 수
- 플러그인별 상세 정보
  - 메타데이터 (버전, 설치 수, 업데이트 날짜)
  - 취약점 목록 (파일 경로, 라인 번호, 코드 스니펫)
  - 심각도 분포
  - 취약점 유형 통계

### HTML 보고서
```
security_results/security_report_20251013_143022.html
```

브라우저에서 바로 확인 가능한 시각화된 보고서:
- 색상으로 구분된 심각도 (빨강: CRITICAL, 주황: HIGH, 노랑: MEDIUM, 초록: LOW)
- 플러그인별 상세 취약점 정보
- 코드 컨텍스트 및 권장사항

## 스캔 결과 예시

```
==============================================================
SECURITY SCAN RESULTS
==============================================================
Plugins scanned: 15
Total vulnerabilities: 47

Severity breakdown:
  🔴 CRITICAL: 8
  🟠 HIGH:     19
  🟡 MEDIUM:   15
  🟢 LOW:      5

Vulnerability types found:
  💉 Xss Direct Output: 12
  🗃️ Sql Injection: 8
  🔐 Csrf Missing: 10
  📁 File Inclusion: 3
  ⚡ Command Injection: 2

Top 5 most vulnerable plugins:
  1. vulnerable-plugin: 12 vulnerabilities
     Main types: XSS: 5, SQL Injection: 4, CSRF: 3
  2. insecure-form: 8 vulnerabilities
     Main types: XSS: 6, CSRF: 2
```

## 고급 기능

### 신뢰도 평가 시스템

스캐너는 각 취약점에 대해 1-100점의 신뢰도 점수를 부여합니다:

- **기본 점수**: 70점
- **안전 함수 사용 시**: -20점
- **관리자 권한 체크 시**: -15점
- **조건문 내부일 경우**: +10점

신뢰도 30점 미만의 탐지는 자동으로 필터링됩니다.

### False Positive 방지

다음 WordPress 안전 함수들을 인식하여 오탐을 줄입니다:

- `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()`
- `sanitize_text_field()`, `sanitize_email()`, `sanitize_url()`
- `wp_kses()`, `wp_kses_post()`
- `intval()`, `absint()`, `floatval()`

### 멀티스레드 처리

최대 10개의 스레드로 병렬 처리하여 대량의 파일을 빠르게 스캔합니다.

## 디렉토리 구조

```
C:\Tools\Wordpress-Plugin-Scanner\
├── advanced_scanner.py          # 메인 스캐너 스크립트
├── downloads\                   # 플러그인 ZIP 파일 및 압축 해제 폴더
│   ├── plugin1\
│   ├── plugin2\
│   └── plugin3\
└── security_results\            # 스캔 결과 보고서
    ├── security_report_20251013_143022.json
    └── security_report_20251013_143022.html
```

## 주의사항

1. **대량 스캔 시**: 많은 플러그인을 스캔할 경우 시간이 오래 걸릴 수 있습니다
2. **메타데이터 수집**: WordPress.org API 호출로 인해 네트워크 연결이 필요합니다
3. **False Positive**: 자동화 도구이므로 수동 검증이 권장됩니다
4. **경로 설정**: 스크립트 내 `base_dir` 경로를 환경에 맞게 수정하세요

## 커스터마이징

### 기본 경로 변경

```python
# advanced_scanner.py의 main() 함수에서 수정
base_dir = r"D:\Your\Custom\Path"
```

### 스레드 수 조정

```python
# scan_all_plugins() 함수에서 수정
with ThreadPoolExecutor(max_workers=20) as executor:  # 기본값: 10
```

### 취약점 패턴 추가

```python
# SecurityScanner 클래스의 __init__에서 패턴 추가
self.vulnerability_patterns['custom_vuln'] = {
    'pattern': r'your_regex_pattern',
    'severity': 'HIGH',
    'description': 'Your vulnerability description',
    'recommendation': 'How to fix it'
}
```
