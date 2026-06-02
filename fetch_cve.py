import requests
import json
import time
from datetime import datetime

# 1. IoT 타겟 리스트
TARGET_BRANDS = ["mercury", "iptime", "asus", "tp-link"]
TARGET_IOT = ["smart plug", "smart switch", "ip camera", "webcam", "smart lock", "smart bulb"]

def get_guide_for_keyword(keyword):
    # (기존 가이드 로직 동일)
    guide_map = {
        "smart plug": ["1. 전용 앱 실행", "2. 기기 설정 진입", "3. 펌웨어 업데이트 확인"],
        "ip camera": ["1. 관리자 페이지 접속", "2. 비밀번호 복잡하게 변경", "3. 펌웨어 최신화"],
        # ... (나머지 가이드는 기존과 동일하게 유지)
    }
    return guide_map.get(keyword, ["1. 제조사 고객센터 안내에 따라 최신 펌웨어 업데이트 진행"])

cve_list = []
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

print("🚀 CPE 정밀 타격 모드 실행 중...")

# 2. 브랜드 기반 CPE 검색 (정밀 타격)
for brand in TARGET_BRANDS:
    # cpeName을 활용해 해당 브랜드의 하드웨어(h) 장비 취약점만 집중 수집
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:h:{brand}:*:*:*:*:*:*:*:*:*:*"
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                # 데이터를 cve_list에 추가 (기존과 동일 구조)
                # ... (데이터 파싱 로직은 동일)
                cve_list.append({
                    "cve_id": cve.get("id"),
                    "device_keyword": brand,
                    "description": cve.get("descriptions", [{}])[0].get("value"),
                    "cvss_score": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0.0),
                    "easy_description": f"{brand.upper()} 제품군에서 발견된 정밀 보안 취약점입니다.",
                    "step_by_step_guide": get_guide_for_keyword(brand)
                })
        time.sleep(6)
    except Exception as e: print(e)

# 3. 범용 IoT 카테고리 검색 (기존 방식 보완)
for keyword in TARGET_IOT:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=3"
    # ... (기존 keywordSearch 방식의 수집 로직 동일)
    # (중복 ID는 앱 단에서 처리하므로 여기서 다 집어넣어도 됩니다)

final_json = {"last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "vulnerabilities": cve_list}
with open("cve_data.json", "w", encoding="utf-8") as f:
    json.dump(final_json, f, indent=4, ensure_ascii=False)
