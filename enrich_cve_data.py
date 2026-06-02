import json
import time
import os
import google.generativeai as genai

# 1. Gemini API 키 설정 (발급받은 키를 여기에 입력하거나 환경변수 사용)
API_KEY = "여기에_발급받은_GEMINI_API_KEY를_넣으세요"
genai.configure(api_key=API_KEY)

# 2. 모델 설정 (최신 Flash 모델 사용)
model = genai.GenerativeModel('gemini-2.5-flash')

def generate_detailed_cve_info(cve_id, description):
    """
    LLM을 사용하여 영문 CVE 원문을 분석하고, 구체적인 원인과 조치법을 한국어로 추출합니다.
    """
    prompt = f"""
    당신은 IoT 보안 전문가입니다. 다음 NVD CVE 원문을 분석하여, 
    일반 사용자도 이해하기 쉬우면서도 '구체적인 해킹 원인(예: 23번 텔넷 포트 노출, 관리자 페이지 XSS, 버퍼 오버플로우 등)'이 명시된 한국어 설명과 조치법을 작성해주세요.
    
    CVE 원문: {description}
    
    반드시 아래 JSON 형식으로만 응답하세요. 다른 설명은 절대 추가하지 마세요.
    {{
        "easyDescription": "여기에 구체적인 취약점 원인이 포함된 한국어 설명 (1~2문장)",
        "actionGuide": "여기에 구체적인 조치 방법 (예: 텔넷 비활성화, 펌웨어 버전 O.O 이상 업데이트 등)"
    }}
    """
    
    try:
        response = model.generate_content(prompt)
        # 응답 텍스트에서 마크다운(```json ... ```) 찌꺼기 제거 후 파싱
        raw_text = response.text.strip().removeprefix('```json').removesuffix('```').strip()
        result = json.loads(raw_text)
        return result['easyDescription'], result['actionGuide']
    except Exception as e:
        print(f"[{cve_id}] LLM 분석 실패: {e}")
        return None, None

def process_cve_file(input_file="cve_data.json", output_file="cve_data_enriched.json"):
    print(f"[{input_file}] 파일을 읽어 AI 분석을 시작합니다...")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    vulnerabilities = data.get("vulnerabilities", [])
    total = len(vulnerabilities)
    
    for i, vuln in enumerate(vulnerabilities):
        cve_id = vuln.get("name", f"Unknown-{i}")
        description = vuln.get("description", "")
        
        # 이미 AI 분석이 된 항목(구체적 내용이 있는 경우)은 스킵할 수 있도록 처리 가능
        # 여기서는 모든 항목을 덮어씌웁니다.
        if description:
            print(f"진행 중... ({i+1}/{total}) : {cve_id} 분석 중")
            
            easy_desc, action_guide = generate_detailed_cve_info(cve_id, description)
            
            if easy_desc and action_guide:
                vuln["easyDescription"] = easy_desc
                vuln["actionGuide"] = action_guide
                
            # 무료 API 속도 제한(Rate Limit) 방지를 위해 약간의 대기 시간 추가
            time.sleep(2) 
            
    # 결과를 새로운 JSON 파일로 저장
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
        
    print(f"\n완료! 업그레이드된 데이터가 [{output_file}]에 저장되었습니다.")

if __name__ == "__main__":
    # 실행부
    process_cve_file("cve_data.json", "cve_data_enriched.json")
