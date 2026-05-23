import requests
import json
import time
from datetime import datetime

# 확장된 글로벌 IoT 기기 수집 타겟 리스트
TARGET_QUERIES = [
    "mercury", "iptime", "asus", "tp-link",           # 네트워크 장비
    "smart plug", "smart switch",                     # 제어/전력
    "ip camera", "webcam", "smart lock", "home hub",  # 보안/허브
    "smart bulb", "air purifier", "robot vacuum",     # 가전/리빙
    "smart speaker", "smart tv"                       # 엔터테인먼트
]

# 기기별 맞춤형 조치 가이드 매핑 시스템
def get_guide_for_keyword(keyword):
    if keyword in ["smart plug", "smart switch"]:
        return [
            "1. 기기 제조사 전용 앱(Tapo, SmartThings 등)을 실행하세요.",
            "2. 연결된 플러그/스위치의 상세 설정 메뉴로 진입합니다.",
            "3. '펌웨어 업데이트' 탭을 눌러 최신 보안 패치를 적용하세요."
        ]
    elif keyword in ["ip camera", "webcam", "smart lock"]:
        return [
            "1. 카메라/도어락 관리자 페이지 또는 전용 연동 앱에 접속하세요.",
            "2. 초기 설정된 관리자 비밀번호를 영문+숫자+특수문자 조합으로 즉시 변경하세요.",
            "3. 외부 원격 접속 기능(P2P/RTSP 등) 중 사용하지 않는 기능은 비활성화하세요.",
            "4. 시스템 최신 펌웨어 업데이트를 강제 진행하세요."
        ]
    elif keyword in ["smart bulb", "air purifier", "robot vacuum", "humidifier"]:
        return [
            "1. 가전 전용 연동 홈 IoT 앱(Mi Home, LG ThinQ, 삼성 SmartThings 등)을 엽니다.",
            "2. 해당 가전 기기를 선택하고 기기 정보 메뉴를 누릅니다.",
            "3. 소프트웨어/펌웨어 버전 업데이트를 수행하세요."
        ]
    elif keyword in ["smart speaker", "smart tv", "smart home hub"]:
        return [
            "1. 기기 화면의 설정 메뉴 또는 스마트폰 연동 앱을 확인합니다.",
            "2. 네트워크 설정에서 공용 와이파이가 아닌 보안이 적용된 홈 와이파이에 연결되었는지 확인하세요.",
            "3. 불필요한 음성 명령 대기 기능이나 원격 스크린캐스트 기능을 제어하고 펌웨어를 최신화하세요."
        ]
    else:
        return [
            "1. 기기와 연결된 PC/스마트폰 브라우저에서 기기 관리 주소로 접속하세요.",
            "2. 제조사 고객지원실에서 공지한 최신 보안 펌웨어를 다운로드하여 업데이트하세요."
        ]

cve_list = []
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

print("🚀 상용화 규격 대규모 IoT 취약점 수집을 시작합니다...")

for keyword in TARGET_QUERIES:
    print(f"[{keyword}] 데이터 추출 중...")
    # NVD API 호출 (각 키워드당 가장 핵심적인 최신 취약점 3개씩만 콤팩트하게 수집)
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
        
    # NVD API 초당 요청 제한(Rate Limit) 방지를 위해 6초간 휴식
    time.sleep(6)

final_json = {
    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "vulnerabilities": cve_list
}

with open("cve_data.json", "w", encoding="utf-8") as f:
    json.dump(final_json, f, indent=4, ensure_ascii=False)

print("✅ 모든 대규모 IoT 카테고리 갱신 완료! cve_data.json 저장 성공.")
