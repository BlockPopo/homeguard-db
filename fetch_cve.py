import requests
import json
import time
from datetime import datetime

TARGET_QUERIES = [
    "mercury", "iptime", "asus", "tp-link",
    "ip camera", "smart plug", "smart switch", "smart lock",
    "smart bulb", "air purifier", "robot vacuum"
]

def get_guide_for_keyword(keyword):
    if keyword in ["smart plug", "smart switch"]:
        return [
            "1. 기기 제조사 전용 앱(Tapo, SmartThings 등)을 실행하세요.",
            "2. 연결된 플러그/스위치의 상세 설정 메뉴로 진입합니다.",
            "3. '펌웨어 업데이트' 탭을 눌러 최신 보안 패치를 적용하세요."
        ]
    elif keyword in ["ip camera", "smart lock"]:
        return [
            "1. 카메라/도어락 관리자 페이지 또는 전용 연동 앱에 접속하세요.",
            "2. 초기 설정된 관리자 비밀번호를 영문+숫자+특수문자 조합으로 즉시 변경하세요.",
            "3. 시스템 최신 펌웨어 업데이트를 강제 진행하세요."
        ]
    else:
        return [
            "1. 기기와 연결된 PC/스마트폰 브라우저에서 기기 관리 주소로 접속하세요.",
            "2. 제조사 고객지원실에서 공지한 최신 보안 펌웨어를 다운로드하여 업데이트하세요."
        ]

cve_list = []
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

print("🚀 데이터 수집 모드로 복구 중 (앱 내부 정밀 필터링 전면 의존)...")

for keyword in TARGET_QUERIES:
    print(f"[{keyword}] 데이터 추출 중...")
    # NVD API 정책에 맞춰 keywordSearch로 검색하되, 
    # 앱에서 모델명을 정밀 매칭할 수 있도록 최신 취약점을 30개씩 넉넉히 가져옵니다.
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
                
                cve_list.append({
                    "cve_id": cve_id,
                    "device_keyword": keyword, 
                    "port": 80,
                    "cvss_score": score,
                    "description": desc,
                    "easy_description": f"{keyword.upper()} 기기 군에서 원격 제어, 사생활 유출 및 악성코드 주입이 가능한 치명적인 취약점이 발견되었습니다.",
                    "danger_keywords": ["IoT 해킹 위협", "원격 권한 탈취", "사생활 노출 위험"],
                    "step_by_step_guide": get_guide_for_keyword(keyword)
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

print("✅ 수집 완료 및 cve_data.json 저장 성공!")
