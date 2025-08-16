# AI Security Dashboard - main.py

import streamlit as st
import pandas as pd

# 페이지 설정
st.set_page_config(
    page_title="AI Security Dashboard",
    page_icon="🔒",
    layout="wide"
)

# Session State 초기화
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# 사이드바 구성
with st.sidebar:
    st.title("AI Security Assistant")
    # 추후 채팅 기능이 여기에 구현될 예정

# 메인 화면 구성
if not st.session_state['analysis_done']:
    # 분석 전 화면
    st.title("AI Security Dashboard")
    
    # 입력 필드
    input_path = st.text_input("분석할 Git Repository URL 또는 로컬 폴더 경로를 입력하세요.")
    
    # 분석 버튼
    if st.button("분석 시작", type="primary"):
        if input_path:  # 입력값이 있을 때만 상태 변경
            st.session_state['analysis_done'] = True
            st.rerun()  # 화면 새로고침
        else:
            st.warning("경로를 입력해주세요.")
            
else:
    # 분석 후 화면
    st.title("AI Security Dashboard")
    
    # 분석 초기화 버튼 (새로운 분석을 위해)
    if st.button("새로운 분석", type="secondary"):
        st.session_state['analysis_done'] = False
        st.rerun()
    
    # 탭 구성
    tab1, tab2 = st.tabs(['SBOM & 취약점 분석', '정적 코드 분석'])
    
    with tab1:
        # SBOM & 취약점 분석 탭 내용
        st.subheader("📊 분석 요약")
        
        # 요약 카드 - 3개의 컬럼으로 나누어 표시
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                label="총 패키지",
                value=124
            )
        
        with col2:
            st.metric(
                label="취약점 발견",
                value=8,
                delta="-3개 (지난 분석 대비)"
            )
        
        with col3:
            st.metric(
                label="라이선스 위험",
                value=2
            )
        
        # 구분선
        st.divider()
        
        # 결과 테이블
        st.subheader("📋 상세 분석 결과")
        
        # 예시 데이터 생성
        data = {
            'Package': ['requests', 'numpy', 'pandas', 'tensorflow', 'django'],
            'Version': ['2.28.1', '1.23.5', '1.5.3', '2.11.0', '4.1.7'],
            'License': ['Apache 2.0', 'BSD 3-Clause', 'BSD 3-Clause', 'Apache 2.0', 'BSD 3-Clause'],
            'License Risk': ['낮음', '낮음', '낮음', '낮음', '낮음'],
            'Vulnerabilities': [2, 0, 0, 5, 1],
            'Highest Severity': ['High', 'N/A', 'N/A', 'Critical', 'Medium']
        }
        df = pd.DataFrame(data)
        
        # 데이터프레임 표시 (인터랙티브 테이블)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Vulnerabilities": st.column_config.NumberColumn(
                    "Vulnerabilities",
                    help="발견된 취약점 개수",
                    format="%d 개"
                ),
                "Highest Severity": st.column_config.TextColumn(
                    "Highest Severity",
                    help="가장 심각한 취약점 수준"
                )
            }
        )
    
    with tab2:
        # 정적 코드 분석 탭
        # 화면을 왼쪽(1/3)과 오른쪽(2/3)으로 분할
        left_col, right_col = st.columns([1, 2])
        
        with left_col:
            # 파일 트리 영역
            st.subheader("분석할 파일 선택")
            
            # 가상의 파일 목록
            file_list = [
                "src/main.py",
                "src/utils.py",
                "src/database.py",  # 예시 취약점 코드가 있는 파일
                "tests/test_main.py"
            ]
            
            # 파일 선택 라디오 버튼 (기본값: src/database.py)
            selected_file = st.radio("파일 목록", file_list, index=2)
            
            # 선택된 파일 정보 표시
            st.info(f"선택된 파일: {selected_file}")
        
        with right_col:
            # 코드 비교 뷰 영역
            st.subheader(f"📄 {selected_file} 분석 결과")
            
            # 오른쪽 컬럼을 다시 두 개로 분할 (원본 코드 vs 수정 코드)
            code_col1, code_col2 = st.columns(2)
            
            with code_col1:
                st.subheader("원본 코드")
                
                # 취약한 SQL 쿼리 예시 코드
                vulnerable_code = """# database.py
def get_user_data(username):
    db_conn = connect_db()
    query = "SELECT * FROM users WHERE username = '" + username + "';"  # 취약점!
    result = db_conn.execute(query).fetchall()
    return result"""
                
                st.code(vulnerable_code, language='python')
            
            with code_col2:
                st.subheader("추천 수정 코드")
                
                # 안전하게 수정된 예시 코드
                fixed_code = """# database.py
def get_user_data(username):
    db_conn = connect_db()
    query = "SELECT * FROM users WHERE username = ?;"  # 수정된 부분
    result = db_conn.execute(query, (username,)).fetchall()
    return result"""
                
                st.code(fixed_code, language='python')
            
            # AI 종합 설명
            st.divider()
            st.warning("""
            **🚨 SQL Injection 취약점 발견**
            
            **문제점**: 사용자 입력을 쿼리에 직접 삽입하여 SQL Injection 공격에 취약합니다.
            
            **해결책**: 매개변수화된 쿼리(Parameterized Query)를 사용하여 방지해야 합니다.
            
            **위험도**: HIGH
            
            **영향**: 공격자가 데이터베이스 전체에 접근하거나 조작할 수 있습니다.
            """)
            
            # 추가 정보
            with st.expander("자세한 설명 보기"):
                st.markdown("""
                ### SQL Injection이란?
                SQL Injection은 웹 애플리케이션의 보안 취약점 중 하나로, 악의적인 SQL 문장을 실행시켜 
                데이터베이스를 비정상적으로 조작하는 공격 기법입니다.
                
                ### 공격 예시
                ```
                username = "admin' OR '1'='1"
                ```
                위와 같은 입력이 들어오면 모든 사용자 정보가 반환될 수 있습니다.
                
                ### 방어 방법
                1. **Prepared Statements** 사용
                2. **입력값 검증** 및 이스케이핑
                3. **최소 권한 원칙** 적용
                4. **정기적인 보안 감사** 실시
                """)