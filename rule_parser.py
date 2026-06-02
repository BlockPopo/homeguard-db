import json
import os

def analyze_vulnerability(description):
    """
    영문 CVE 원문의 키워드를 분석하여 한국어 설명과 조치법을 반환합니다.
    """
    desc = description.lower()
    
    # 1. 텔넷 / 포트 노출
    if "telnet" in desc or "port 23" in desc:
        return "텔넷(Telnet) 포트가 외부에 노출되어 해커가 무단으로 접속할 수 있는 취약점입니다.", "기기 설정에서 Telnet 기능을 비활성화하고 외부 접속을 차단하세요."
    
    # 2. RCE (원격 코드 실행) / Command Injection
    elif "rce" in desc or "command injection" in desc or "arbitrary code" in desc:
        return "입력값 검증 미흡으로 인해 해커가 원격에서 최고 권한으로 악성 명령을 실행할 수 있는 치명적인 취약점입니다.", "외부망(WAN) 접근을 즉시 차단하고 최신 펌웨어로 업데이트하세요."
    
    # 3. XSS (크로스 사이트 스크립팅)
    elif "xss" in desc or "cross-site scripting" in desc:
        return "관리자 웹 페이지에 크로스 사이트 스크립팅(XSS) 취약점이 존재하여, 접속 시 악성 스크립트가 실행될 수 있습니다.", "신뢰할 수 없는 기기에서 관리자 페이지 접근을 차단하고 펌웨어를 패치하세요."
    
    # 4. 버퍼 오버플로우
    elif "buffer overflow" in desc or "memory corruption" in desc:
        return "메모리 버퍼 오버플로우 취약점으로 인해 기기가 다운되거나 악성 코드가 실행될 수 있습니다.", "메모리 보호가 적용된 최신 펌웨어 버전으로 즉시 업데이트하세요."
    
    # 5. 하드코딩된 비밀번호 / 인증 우회
    elif "hardcoded" in desc or "default password" in desc or "bypass authentication" in desc:
        return "기기에 비밀번호가 하드코딩되어 있거나 인증 우회가 가능하여 누구나 관리자 권한을 탈취할 수 있습니다.", "기본 비밀번호를 복잡하게 변경하고, 제조사 패치를 적용하세요."
    
    # 6. 기타 (기본 템플릿)
    else:
        return "기기 펌웨어 또는 설정에 알려진 보안 취약점이 존재합니다.", "제조사 홈페이지를 확인하여 최신 펌웨어로 업데이트하세요."

def process_cve_data(file_path="cve_data.json"):
    print("룰 기반 취약점 분석을 시작합니다...")
    
    if not os.path.exists(file_path):
        print(f"오류: {file_path} 파일이 없습니다.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    vulnerabilities = data.get("vulnerabilities", [])
    
    for vuln in vulnerabilities:
        description = vuln.get("description", "")
        # 원문이 존재하면 룰 기반 매핑 적용
        if description:
            easy_desc, action_guide = analyze_vulnerability(description)
            vuln["easyDescription"] = easy_desc
            vuln["actionGuide"] = action_guide

    # 결과 덮어쓰기
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
        
    print("분석 완료! cve_data.json이 업데이트되었습니다.")

if __name__ == "__main__":
    process_cve_data()
