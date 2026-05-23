import requests
import json
import time
from datetime import datetime

# 타겟 제조사 리스트 (앱에서 스캔될 확률이 높은 주요 브랜드)
TARGET_BRANDS = ["iptime", "asus", "tp-link", "netgear", "mercury"]

# 제조사별 맞춤형 조치 가이드 매핑 (각 기기별 설정 페이지 주소가 다름)
GUIDE_MAP = {
    "iptime": ["1. 브라우저에서 192.168.0.1로 접속하세요.", "2. 관리자 계정으로 로그인 후 '시스템 설정'으로 이동하세요.", "3. '펌웨어 업그레이드'를 실행하세요."],
    "asus": ["1. 브라우저에서 router.asus.com으로 접속하세요.", "2. 관리자 로그인 후 좌측 하단의 '관리' 탭으로 이동하세요.", "3. '펌웨어 업그레이드' 탭에서 업데이트를 확인하세요."],
    "tp-link": ["1. 브라우저에서 tplinkwifi.net으로 접속하세요.", "2. 시스템 도구 -> 펌웨어 업그레이드로 이동하여 최신 버전을 설치하세요."],
    "netgear": ["1. 브라우저에서 routerlogin.net으로 접속하세요.", "2. 고급(Advanced) -> 라우터 업데이트(Router Update)를 클릭하세요."],
    "mercury": ["1. 브라우저에서 192.168.1.1로 접속하세요.", "2. 설정 화면에서 최신 펌웨어를 확인하고 업데이트하세요."]
}

cve_list = []

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

print("🚀 실제 제조사별 취약점 데이터 수집을 시작합니다...")

for brand in TARGET_BRANDS:
    print(f"[{brand}] 취약점 검색 중...")
    # 각 브랜드별 최신 취약점 3개씩 수집
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={brand}&resultsPerPage=3"
    
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
                    "device_keyword": brand, # OCR로 뽑아낼 브랜드명과 정확히 매핑됨
                    "port": 80,
                    "cvss_score": score,
                    "description": desc,
                    "easy_description": f"{brand.upper()} 기기에서 보안 취약점이 발견되었습니다. 펌웨어 구멍을 통해 해커가 침입할 수 있습니다.",
                    "danger_keywords": ["기기 취약점", "펌웨어 위험"],
                    "step_by_step_guide": GUIDE_MAP.get(brand, ["제조사 홈페이지에서 최신 펌웨어를 다운로드하여 설치하세요."])
                })
        else:
            print(f"[{brand}] 데이터 가져오기 실패 (상태 코드: {response.status_code})")
            
    except Exception as e:
        print(f"[{brand}] 처리 중 에러 발생: {e}")
        
    # ⚠️ 매우 중요: NVD API는 무료 사용자(키 없음)가 짧은 시간에 너무 많이 요청하면 차단합니다.
    # 각 브랜드 검색 사이에 무조건 6초를 쉬어주어야 에러 없이 끝까지 돌아갑니다.
    time.sleep(6)

final_json = {
    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "vulnerabilities": cve_list
}

with open("cve_data.json", "w", encoding="utf-8") as f:
    json.dump(final_json, f, indent=4, ensure_ascii=False)

print("✅ 모든 데이터 수집 완료! cve_data.json 저장 성공.")
