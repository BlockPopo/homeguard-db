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
    영문 원문(description)과 기기 종류(keyword)를 종합적으로 분석하여
    완전한 일반인 눈높이에 맞춘 '설명'과 '조치법'을 반환합니다.
    """
    desc = description.lower() if description else ""
    
    # 1. 기기 분류: 공유기인가, 그 외 스마트 가전(IoT)인가?
    routers = ["iptime", "asus", "tp-link", "mercury"]
    is_router = keyword.lower() in routers

    # -------------------------------------------------------------
    # [상황 1] 비밀번호가 없거나 기본 비밀번호(0000 등)로 뚫리는 경우
    # -------------------------------------------------------------
    if "password" in desc or "hardcoded" in desc or "default" in desc or "bypass" in desc or "authentication" in desc:
        if is_router:
            return (
                "공유기의 관리자 설정 문이 활짝 열려있어, 외부에서 누구나 공유기를 마음대로 조작할 수 있는 위험한 상태입니다.",
                [
                    "1. 이 앱의 [조치하기] 버튼을 눌러 공유기 설정 화면으로 들어가세요.",
                    "2. '시스템 관리'나 '관리자 설정' 메뉴를 찾으세요.",
                    "3. 누구나 알 수 있는 기본 비밀번호(admin 등)를 영문과 숫자가 섞인 복잡한 비밀번호로 꼭 바꿔주세요."
                ]
            )
        else:
            return (
                f"누구나 알 수 있는 기본 비밀번호로 설정되어 있거나, 인증 과정에 문제가 있어 남이 {keyword.upper()} 기기를 몰래 훔쳐보거나 조종할 수 있습니다.",
                [
                    "1. 스마트폰에서 이 기기를 조작할 때 쓰는 '전용 앱'을 켜주세요.",
                    "2. 기기 설정이나 내 정보 메뉴로 들어가 '비밀번호 변경' 항목을 찾으세요.",
                    "3. 이름이나 생일이 아닌, 유추하기 어려운 복잡한 비밀번호로 당장 바꿔주세요."
                ]
            )

    # -------------------------------------------------------------
    # [상황 2] 기기 자체의 업데이트 시스템에 구멍이 난 경우 (로봇청소기 등)
    # -------------------------------------------------------------
    elif "update" in desc or "firmware" in desc or "over-the-air" in desc:
        if is_router:
            return (
                "공유기를 작동시키는 소프트웨어(펌웨어)에 보안 구멍이 발견되었습니다. 해커가 이를 악용해 네트워크를 마비시킬 수 있습니다.",
                [
                    "1. 이 앱의 [조치하기] 버튼을 눌러 공유기 설정 화면으로 이동하세요.",
                    "2. 메뉴에서 '펌웨어 업그레이드' 또는 '시스템 업데이트' 항목을 찾으세요.",
                    "3. '자동 업그레이드' 버튼을 누르거나 최신 버전을 적용해 주세요."
                ]
            )
        else:
            return (
                f"{keyword.upper()} 기기를 최신 상태로 업데이트하는 과정에서 해커가 가짜 악성 파일을 끼워 넣을 수 있는 취약점입니다.",
                [
                    "1. 평소에 집에서 쓰시는 와이파이에 스마트폰이 연결되어 있는지 확인하세요.",
                    "2. 스마트폰에서 해당 기기를 조작하는 '전용 앱(Tapo, Mi Home 등)'을 켜주세요.",
                    "3. 앱 안의 기기 설정 메뉴로 들어가 '소프트웨어(펌웨어) 업데이트' 버튼을 눌러 안전한 최신 버전으로 만들어주세요.",
                    "4. 업데이트가 완전히 끝날 때까지 기기의 전원을 끄거나 코드를 뽑지 마세요."
                ]
            )

    # -------------------------------------------------------------
    # [상황 3] 기기간 통신이 암호화되지 않아 가로채기가 가능한 경우
    # -------------------------------------------------------------
    elif "encryption" in desc or "insecure wi-fi" in desc or "intercept" in desc or "key" in desc:
        return (
            f"{keyword.upper()} 기기와 스마트폰이 대화하는 과정이 암호화되지 않아, 근처에 있는 해커가 개인정보나 조작 신호를 가로챌 수 있습니다.",
            [
                "1. 스마트폰에서 기기 전용 앱을 켜주세요.",
                "2. 기기 설정에서 '최신 소프트웨어(펌웨어) 업데이트'를 진행하여 제조사가 제공하는 보안 패치를 적용하세요.",
                "3. 가급적 비밀번호가 없는 공개 와이파이(카페, 지하철 등)에서는 기기 조작을 피해 주세요."
            ]
        )

    # -------------------------------------------------------------
    # [상황 4] 원격 조종 / 시스템 파괴 (RCE, Buffer Overflow 등)
    # -------------------------------------------------------------
    elif "rce" in desc or "command injection" in desc or "arbitrary code" in desc or "buffer overflow" in desc:
        if is_router:
            return (
                "공유기에 해커가 원격으로 접속해 악성코드를 심거나 인터넷을 마음대로 끊어버릴 수 있는 매우 심각한 상태입니다.",
                [
                    "1. 이 앱의 [조치하기] 버튼을 눌러 공유기 관리자 화면으로 들어가세요.",
                    "2. '보안 설정'이나 '방화벽 설정' 메뉴에서 외부에서 접속하는 기능(원격 관리 등)이 켜져 있다면 당장 꺼주세요.",
                    "3. '시스템 관리' 메뉴로 이동해 최신 버전으로 업그레이드를 진행하세요."
                ]
            )
        else:
            return (
                f"해커가 멀리서 {keyword.upper()} 기기를 마음대로 조종하거나 기기를 망가뜨릴 수 있는 치명적인 결함이 발견되었습니다.",
                [
                    "1. 즉시 스마트폰에서 기기 전용 앱을 켜고 최신 소프트웨어(펌웨어) 업데이트를 진행하세요.",
                    "2. 만약 제조사에서 아직 업데이트를 만들어주지 않았다면, 당분간 기기의 전원을 끄고 사용을 멈추는 것이 가장 안전합니다."
                ]
            )

    # -------------------------------------------------------------
    # [기본 상황] 특정 키워드가 없는 기타 취약점
    # -------------------------------------------------------------
    else:
        if is_router:
            return (
                "공유기의 내부 설정이나 시스템에 보안 전문가들이 발견한 취약점이 존재합니다.",
                [
                    "1. 이 앱의 [조치하기] 버튼을 눌러 공유기 설정 화면에 들어가세요.",
                    "2. '펌웨어 업그레이드' 메뉴를 찾아 가장 최신 버전으로 업데이트 버튼을 눌러주세요."
                ]
            )
        else:
            return (
                f"{keyword.upper()} 기기의 소프트웨어에 해커가 악용할 수 있는 보안 취약점이 보고되었습니다.",
                [
                    "1. 스마트폰에서 해당 기기의 전용 앱을 실행해 주세요.",
                    "2. 설정 메뉴를 열어 기기를 최신 소프트웨어(펌웨어)로 업데이트해 주세요."
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
