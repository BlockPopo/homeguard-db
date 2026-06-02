import requests
import json
import time
from datetime import datetime

TARGET_QUERIES = [
    "mercury", "iptime", "asus", "tp-link",
    "ip camera", "smart plug", "smart switch", "smart lock",
    "smart bulb", "air purifier", "robot vacuum"
]

def analyze_vulnerability(description, keyword):
    """
    영문 CVE 원문의 키워드를 분석하여, 
    앱에 보여줄 '구체적인 한국어 설명'과 '단계별 조치법(리스트)'을 반환합니다.
    """
    if not description or description == "No description":
        return (
            f"{keyword.upper()} 기기에서 알려진 보안 취약점이 존재합니다.",
            ["1. 제조사 홈페이지를 확인하여 최신 펌웨어로 업데이트하세요."]
        )
        
    desc = description.lower()
    
    # 1. 텔넷 / 포트 노출
    if "telnet" in desc or "port 23" in desc or "open port" in desc:
        return (
            "관리용 포트(Telnet 등)가 외부에 노출되어 해커가 무단으로 접속할 수 있는 취약점입니다.",
            [
                "1. 기기 관리자 페이지에 접속하세요.",
                "2. 설정에서 불필요한 포트(23번 등) 및 Telnet 기능을 비활성화하세요.",
                "3. 외부망(WAN) 접속 기능을 즉시 차단하세요."
            ]
        )
    # 2. RCE / Command Injection (원격 제어)
    elif "rce" in desc or "command injection" in desc or "arbitrary code" in desc:
        return (
            "입력값 검증 미흡으로 인해 해커가 원격에서 최고 권한으로 악성 명령을 실행할 수 있는 치명적인 취약점입니다.",
            [
                "1. 기기를 인터넷(외부망)과 즉시 분리하세요.",
                "2. 제조사 홈페이지에서 제공하는 최신 보안 펌웨어를 다운로드하여 수동 업데이트하세요."
            ]
        )
    # 3. XSS (스크립트 삽입)
    elif "xss" in desc or "cross-site scripting" in desc:
        return (
            "관리자 웹 페이지에 크로스 사이트 스크립팅(XSS) 취약점이 존재하여, 접속 시 악성 스크립트가 실행될 수 있습니다.",
            [
                "1. 신뢰할 수 없는 공용 와이파이에서의 기기 관리를 금지하세요.",
                "2. 관리자 페이지 접근을 차단하고 최신 펌웨어를 패치하세요."
            ]
        )
    # 4. 버퍼 오버플로우
    elif "buffer overflow" in desc or "memory corruption" in desc:
        return (
            "메모리 버퍼 오버플로우 취약점으로 인해 기기가 다운되거나 악성 코드가 실행될 수 있습니다.",
            [
                "1. 메모리 보호가 적용된 최신 펌웨어 버전으로 즉시 업데이트하세요.",
                "2. 업데이트 전까지 불필요한 네트워크 기능을 끄세요."
            ]
        )
    # 5. 하드코딩 / 인증 우회
    elif "hardcoded" in desc or "default password" in desc or "bypass authentication" in desc:
        return (
            "기기에 비밀번호가 출고 상태로 고정되어 있거나 인증 우회가 가능하여 누구나 관리자 권한을 탈취할 수 있습니다.",
            [
                "1. 관리자 계정의 기본 비밀번호를 영문+숫자+특수문자 조합으로 즉시 변경하세요.",
                "2. 제조사 보안 패치를 적용하세요."
            ]
        )
    # 6. 기본 템플릿
    else:
        return (
            f"{keyword.upper()} 기기 펌웨어 또는 네트워크 설정에 보안 취약점이 발견되었습니다.",
            [
                "1. 기기와 연결된 PC/스마트폰 브라우저에서 기기 관리 주소로 접속하세요.",
                "2. 제조사 고객지원실에서 공지한 최신 보안 펌웨어를 다운로드하여 업데이트하세요."
            ]
        )

cve_list = []
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

print("🚀 룰 기반(Rule-based) 데이터 수집 및 자동 분석 모드 시작...")

for keyword in TARGET_QUERIES:
    print(f"[{keyword}] 데이터 추출 중...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=30"
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")
                
                descriptions = cve.get("descriptions", [])
                desc = descriptions[0].get("value", "No description") if descriptions else "No description"
                
                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                
                # ★ 여기서 영문 원문을 분석해서 한국어 설명과 가이드를 뽑아냄!
                easy_desc, step_guide = analyze_vulnerability(desc, keyword)
                
                # 추출된 데이터를 회원님의 기존 구조에 맞춰 저장
                cve_list.append({
                    "cve_id": cve_id,
                    "device_keyword": keyword, 
                    "port": 80,
                    "cvss_score": score,
                    "description": desc,
                    "easy_description": easy_desc,         # 변경됨 (룰 기반 맞춤형)
                    "danger_keywords": ["IoT 해킹 위협", "원격 권한 탈취", "사생활 노출 위험"],
                    "step_by_step_guide": step_guide       # 변경됨 (룰 기반 맞춤형)
                })
        else:
            print(f"[{keyword}] 수집 실패 (상태 코드: {response.status_code})")
    except Exception as e:
        print(f"[{keyword}] 에러 발생: {e}")
        
    time.sleep(6) # Rate Limit 차단 방지

final_json = {
    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "vulnerabilities": cve_list
}

with open("cve_data.json", "w", encoding="utf-8") as f:
    json.dump(final_json, f, indent=4, ensure_ascii=False)

print("✅ 수집 및 룰 기반 분석 완료! cve_data.json 저장 성공!")
