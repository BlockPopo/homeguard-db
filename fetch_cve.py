import requests
import json
from datetime import datetime

# NVD 공식 무료 API (키 없이 사용 가능, router 관련 최신 취약점 5개 검색)
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=router&resultsPerPage=5"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

try:
    print("NVD API에서 실제 취약점 데이터를 가져오는 중...")
    response = requests.get(URL, headers=headers, timeout=15)
    data = response.json()
    
    cve_list = []
    
    # NVD의 복잡한 원본 데이터에서 우리가 필요한 것만 추출
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        
        # 원문 설명 (영어)
        descriptions = cve.get("descriptions", [])
        desc = descriptions[0].get("value", "No description") if descriptions else "No description"
        
        # CVSS 점수 추출 (V3.1 기준)
        metrics = cve.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        score = cvss_data.get("baseScore", 0.0)
        
        # 우리 앱이 읽을 수 있는 형태로 재조립 (파싱)
        cve_list.append({
            "cve_id": cve_id,
            "device_keyword": "router", 
            "port": 80,
            "cvss_score": score,
            "description": desc,
            # 실제 상용화 시 이 부분에 파파고 API나 LLM 연동이 들어갑니다. 지금은 기본값으로 세팅.
            "easy_description": "기기 펌웨어 취약점이 발견되었습니다.",
            "danger_keywords": ["네트워크 위험", "원격접근"],
            "step_by_step_guide": [
                "제조사 홈페이지에 접속하세요.",
                "최신 펌웨어 버전을 다운로드하여 설치하세요."
            ]
        })
        
    # 최종 JSON 껍데기 포맷
    final_json = {
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": cve_list
    }
    
    # cve_data.json 파일로 저장
    with open("cve_data.json", "w", encoding="utf-8") as f:
        json.dump(final_json, f, indent=4, ensure_ascii=False)
        
    print("성공! 실제 데이터를 cve_data.json에 저장했습니다.")

except Exception as e:
    print(f"데이터를 가져오는 중 에러가 발생했습니다: {e}")
