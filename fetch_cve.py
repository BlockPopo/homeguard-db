import requests
import json
import time
from datetime import datetime

# 라우터를 넘어선 진짜 IoT 타겟 리스트 (브랜드 및 기기군)
TARGET_QUERIES = [
    "mercury", "iptime", "asus", # 기본 네트워크 장비
    "smart plug", "smart switch", # 전력 제어 IoT
    "ip camera", "webcam", "cctv" # 보안/모니터링 IoT
]

# 기기군에 따른 맞춤형 한글 가이드 (앱 화면에 예쁘게 나오도록 세팅)
def get_guide_for_keyword(keyword):
    if keyword in ["smart plug", "smart switch"]:
        return [
            "1. 해당 스마트기기의 전용 모바일 앱(예: Tapo, SmartThings 등)을 엽니다.",
            "2. 기기 설정(톱니바퀴 아이콘) 메뉴로 들어갑니다.",
            "3. '기기 정보' 또는 '펌웨어 업데이트' 항목에서 최신 버전으로 업데이트하세요."
        ]
    elif keyword in ["ip camera", "webcam", "cctv"]:
        return [
            "1. 카메라 제조사의 전용 앱이나 PC 뷰어 프로그램에 접속하세요.",
            "2. 관리자 비밀번호가 초기 상태(admin/0000 등)라면 즉시 특수문자를 포함해 변경하세요.",
            "3. 시스템 설정에서 펌웨어를 최신으로 올리고, 안 쓰는 포트는 닫아두세요."
        ]
    else:
        return [
            "1. 기기와 연결된 PC/스마트폰 브라우저에서 관리자 페이지(예: 192.168.0.1)로 접속하세요.",
            "2. 최신 펌웨어로 업데이트를 진행하세요."
        ]

cve_list = []
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

print("🚀 실제 IoT 기기 취약점 데이터 수집을 시작합니다...")

for keyword in TARGET_QUERIES:
    print(f"[{keyword}] 관련 IoT 취약점 검색 중...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=3"
    
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
                    "device_keyword": keyword, # 한글 검색 시 치환될 영문 베이스
                    "port": 80,
                    "cvss_score": score,
                    "description": desc,
                    "easy_description": f"{keyword.upper()} 기기에서 원격 제어 및 정보 유출이 가능한 보안 취약점이 발견되었습니다.",
                    "danger_keywords": ["IoT 보안 위협", "해킹 가능성", "사생활 노출"],
                    "step_by_step_guide": get_guide_for_keyword(keyword)
                })
        else:
            print(f"[{keyword}] 수집 실패 (상태 코드: {response.status_code})")
    except Exception as e:
        print(f"[{keyword}] 에러: {e}")
        
    time.sleep(6) # NVD API 차단 방지 (필수)

final_json = {
    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "vulnerabilities": cve_list
}

with open("cve_data.json", "w", encoding="utf-8") as f:
    json.dump(final_json, f, indent=4, ensure_ascii=False)

print("✅ IoT 타겟 수집 완료! cve_data.json 저장 성공.")
