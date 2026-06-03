# 🛡️ AIHomeGuard - CVE Data Fetcher Bot

4학년 캡스톤 디자인 1학기에 실시한 AIHomeGuard 안드로이드 클라이언트 앱에 최신 보안 위협 정보를 제공하기 위한 **Python 기반 지능형 CVE 수집 및 자동 가공 봇**입니다.

단순히 영문 취약점(CVE) 원문을 가져오는 것을 넘어, 일반 사용자가 이해하기 어려운 보안 용어를 분석하여 **'디바이스 맞춤형 3단계 한국어 조치 가이드'**로 변환하고 JSON 형태로 클라이언트에 공급하는 데이터 파이프라인 역할을 수행합니다.

## ✨ 주요 기능 (Key Features)

- **최신 취약점 자동 수집:** 주기적으로 최신 네트워크 장비 및 홈 IoT 기기 관련 CVE(Common Vulnerabilities and Exposures) 데이터를 수집합니다.
- **위협 유형 자동 분류 (Threat Categorization):**
  - 수집된 CVE의 원문(Description)을 자연어 키워드 알고리즘으로 분석합니다.
  - 인증 우회(Auth Bypass), 원격 코드 실행(RCE), 암호화 결함 등 해킹 유형을 식별합니다.
- **초보자 맞춤형 가이드 생성:** 식별된 위협 유형과 대상 기기(공유기 vs 일반 IoT)를 바탕으로, 모바일 앱에서 즉시 렌더링할 수 있는 '한국어 3단계 조치 가이드'를 동적으로 생성합니다.
- **JSON 파이프라인 구축:** 안드로이드 클라이언트가 파싱하기 쉬운 경량화된 JSON 데이터(`cve_data.json`) 형식으로 결과물을 출력하여 단방향 데이터 흐름(UDF)을 지원합니다.

## ⚙️ 시스템 아키텍처 (Data Flow)

1. **Fetch:** NVD(National Vulnerability Database) 또는 외부 취약점 API로부터 최신 JSON 데이터 수집
2. **Analyze:** `fetch_cve.py` 내부의 휴리스틱 알고리즘을 통해 대상 기기(Router/IoT) 및 위협 벡터 분석
3. **Generate:** 한국어 조치 텍스트 매핑 및 메타데이터(수집 일자 등) 주입
4. **Export:** 앱 클라이언트가 접근할 수 있는 `cve_data.json` 파일 갱신

## 🚀 설치 및 실행 방법 (Getting Started)

### 요구 사항 (Prerequisites)
- Python 3.8 이상
- `requests` 라이브러리

## 설치 (Installation)

### 저장소 클론
git clone https://github.com/your-repo/AIHomeGuard-CVE-Bot.git(https://github.com/your-repo/AIHomeGuard-CVE-Bot.git)
cd AIHomeGuard-CVE-Bot

### 의존성 패키지 설치
pip install requests

## 📄 데이터 출력 예시 (JSON Output Format)

모바일 클라이언트의 동적 라우팅 및 렌더링을 위해 가공된 JSON 데이터의 예시입니다.

[
  {
    "cve_id": "CVE-2026-12345",
    "target_device": "Router",
    "device_keyword": "iptime",
    "threat_type": "원격 제어 및 인증 우회",
    "severity": "CRITICAL",
    "description": "특정 펌웨어 버전에서 원격 공격자가 관리자 권한을 획득할 수 있는 취약점입니다.",
    "mitigation_guide_kr": [
      "1. 하단의 '공유기 설정' 버튼을 눌러 관리자 페이지에 접속하세요.",
      "2. 시스템 설정 메뉴에서 최신 펌웨어 버전으로 업데이트를 진행하세요.",
      "3. 기본 설정된 관리자 비밀번호를 영문/숫자 혼합으로 변경하세요."
    ],
    "action_type": "ROUTER_WEBVIEW",
    "last_updated": "2026-06-04"
  }
]
