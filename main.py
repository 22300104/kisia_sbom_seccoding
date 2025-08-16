# AI Security Dashboard - main.py

import streamlit as st
import pandas as pd
import time
from analysis import analyze_project

# 페이지 설정
st.set_page_config(
    page_title="AI Security Dashboard",
    page_icon="🔒",
    layout="wide"
)

# Session State 초기화
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False
if 'result_df' not in st.session_state:
    st.session_state['result_df'] = pd.DataFrame()
if 'summary' not in st.session_state:
    st.session_state['summary'] = {}

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
        if not input_path:
            st.warning("분석할 Git Repository URL 또는 로컬 폴더 경로를 입력해주세요.")
        else:
            # 에러 표시를 위한 컨테이너
            error_container = st.container()
            
            # 분석 진행
            with st.spinner('프로젝트를 분석 중입니다... 잠시만 기다려주세요.'):
                try:
                    # analyze_project 함수 호출
                    df, summary = analyze_project(input_path)
                    
                    # 디버깅 정보 출력 (항상 표시, session_state 저장 전에)
                    with error_container:
                        st.info("📊 분석 완료. 결과를 확인하고 있습니다...")
                        
                        with st.expander("🔍 디버깅 정보 (클릭하여 펼치기)", expanded=True):
                            st.write("**분석 결과 요약:**")
                            st.json(summary)
                            st.write("**DataFrame 정보:**")
                            st.write(f"- 행 개수: {len(df)}")
                            st.write(f"- 열: {list(df.columns) if not df.empty else 'DataFrame이 비어있음'}")
                            if not df.empty:
                                st.write("**처음 5개 행:**")
                                st.dataframe(df.head())
                            else:
                                st.warning("⚠️ DataFrame이 비어있습니다. 패키지를 찾지 못했습니다.")
                            
                            # 입력 경로 정보
                            st.write("**입력 정보:**")
                            st.write(f"- 입력 경로: {input_path}")
                            st.write(f"- 경로 타입: {'Git URL' if 'http' in input_path or '.git' in input_path else '로컬 경로'}")
                    
                    # 에러가 summary에 포함되어 있는지 먼저 확인
                    if 'error' in summary:
                        with error_container:
                            st.error(f"⚠️ 분석 중 오류가 발생했습니다")
                            st.code(summary['error'], language=None)
                            st.info("💡 위 오류는 필수 도구가 설치되지 않았거나, 프로젝트 구조를 인식할 수 없을 때 발생합니다.")
                            
                            with st.expander("🛠️ 문제 해결 도움말"):
                                st.markdown("""
                                ### 필수 도구 설치 방법:
                                
                                **Windows:**
                                1. Git: https://git-scm.com/download/win
                                2. Syft: PowerShell에서 실행
                                   ```
                                   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .
                                   ```
                                3. OSV-Scanner: Go 설치 후
                                   ```
                                   go install github.com/google/osv-scanner/cmd/osv-scanner@latest
                                   ```
                                
                                **Mac/Linux:**
                                1. Git: `brew install git` 또는 `apt-get install git`
                                2. Syft: 터미널에서 실행
                                   ```
                                   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
                                   ```
                                3. OSV-Scanner: Go 설치 후
                                   ```
                                   go install github.com/google/osv-scanner/cmd/osv-scanner@latest
                                   ```
                                
                                ### 도구 없이 기본 분석만 사용하려면:
                                - requirements.txt 파일이 있는 Python 프로젝트 경로를 입력하세요
                                - 기본적인 의존성 분석은 가능하지만 취약점 검사는 제한적입니다
                                """)
                        # 에러가 있으면 session_state를 저장하지 않음 (화면 전환 방지)
                        st.stop()  # 여기서 실행을 중단
                    
                    # 결과가 비어있는지 확인
                    elif df.empty or summary.get('total_packages', 0) == 0:
                        with error_container:
                            st.warning("⚠️ 분석은 완료되었지만 패키지를 찾지 못했습니다.")
                            st.info("""
                            가능한 원인:
                            1. requirements.txt 파일이 프로젝트 루트에 없음
                            2. 도구가 설치되지 않아 fallback 모드로 실행됨
                            3. 프로젝트 경로가 잘못됨
                            
                            위의 디버깅 정보를 확인해주세요.
                            """)
                            
                            # 사용자가 확인할 수 있도록 버튼 제공
                            if st.button("그래도 결과 화면으로 이동", type="primary"):
                                # 빈 결과라도 저장하고 화면 전환
                                st.session_state.result_df = df
                                st.session_state.summary = summary
                                st.session_state.analysis_done = True
                                st.rerun()
                        st.stop()  # 여기서 실행을 중단
                    
                    # 정상적으로 패키지를 찾은 경우에만 여기 도달
                    else:
                        # 결과를 session_state에 저장
                        st.session_state.result_df = df
                        st.session_state.summary = summary
                        st.session_state.analysis_done = True
                        
                        with error_container:
                            st.success(f"✅ 분석이 완료되었습니다! {summary.get('total_packages', 0)}개의 패키지를 발견했습니다.")
                        
                        time.sleep(2)  # 성공 메시지를 잠시 보여줌
                        st.rerun()  # 화면 새로고침
                        
                except Exception as e:
                    with error_container:
                        st.error("🔴 분석 중 예상치 못한 오류가 발생했습니다")
                        st.exception(e)  # 상세 에러 로그를 화면에 표시
                        
                        # 추가 도움말
                        with st.expander("🛠️ 문제 해결 도움말"):
                            st.markdown("""
                            ### 일반적인 해결 방법:
                            
                            1. **경로 확인**: 입력한 경로가 올바른지 확인하세요
                            2. **Git URL**: `https://github.com/username/repo.git` 형식인지 확인
                            3. **로컬 경로**: 절대 경로 사용 (예: `C:/projects/myproject` 또는 `/home/user/project`)
                            4. **Python 프로젝트**: requirements.txt 파일이 있는지 확인
                            
                            ### 필수 도구 설치 상태:
                            - Git, Syft, OSV-Scanner가 필요합니다
                            - 도구 없이 기본 분석만 원하시면 requirements.txt가 있는 프로젝트를 사용하세요
                            """)
                        
                        # 에러 정보 복사를 위한 버튼
                        if st.button("📋 에러 정보 복사용 텍스트 보기"):
                            st.text_area("에러 정보 (복사하여 사용)", value=str(e), height=200)
            
else:
    # 분석 후 화면
    st.title("AI Security Dashboard")
    
    # 분석 초기화 버튼 (새로운 분석을 위해)
    if st.button("새로운 분석", type="secondary"):
        st.session_state['analysis_done'] = False
        st.session_state['result_df'] = pd.DataFrame()
        st.session_state['summary'] = {}
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
                value=st.session_state.summary.get('total_packages', 0)
            )
        
        with col2:
            vulnerabilities = st.session_state.summary.get('vulnerabilities_found', 0)
            st.metric(
                label="취약점 발견",
                value=vulnerabilities,
                delta=f"{vulnerabilities}개 발견" if vulnerabilities > 0 else "안전"
            )
        
        with col3:
            st.metric(
                label="라이선스 위험",
                value=st.session_state.summary.get('license_risks', 0)
            )
        
        # 구분선
        st.divider()
        
        # 결과 테이블
        st.subheader("📋 상세 분석 결과")
        
        # 실제 분석 결과 DataFrame 표시
        if not st.session_state.result_df.empty:
            # 취약점이 있는 패키지를 상단에 표시하도록 정렬
            sorted_df = st.session_state.result_df.sort_values(
                by='Vulnerabilities', 
                ascending=False
            )
            
            # 데이터프레임 표시 (인터랙티브 테이블)
            st.dataframe(
                sorted_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Package": st.column_config.TextColumn(
                        "Package",
                        help="패키지 이름",
                        width="medium"
                    ),
                    "Version": st.column_config.TextColumn(
                        "Version",
                        help="패키지 버전",
                        width="small"
                    ),
                    "License": st.column_config.TextColumn(
                        "License",
                        help="패키지 라이선스",
                        width="medium"
                    ),
                    "License Risk": st.column_config.TextColumn(
                        "License Risk",
                        help="라이선스 위험도",
                        width="small"
                    ),
                    "Vulnerabilities": st.column_config.NumberColumn(
                        "Vulnerabilities",
                        help="발견된 취약점 개수",
                        format="%d 개",
                        width="small"
                    ),
                    "Highest Severity": st.column_config.TextColumn(
                        "Highest Severity",
                        help="가장 심각한 취약점 수준",
                        width="small"
                    )
                }
            )
            
            # 취약점이 발견된 경우 추가 정보 표시
            if st.session_state.summary.get('vulnerabilities_found', 0) > 0:
                st.info(f"⚠️ 총 {st.session_state.summary['vulnerabilities_found']}개의 취약점이 발견되었습니다. 보안 패치를 적용하는 것을 권장합니다.")
            else:
                st.success("✅ 알려진 취약점이 발견되지 않았습니다.")
                
            # 라이선스 위험이 있는 경우 추가 정보 표시
            if st.session_state.summary.get('license_risks', 0) > 0:
                st.warning(f"📜 {st.session_state.summary['license_risks']}개의 패키지에서 라이선스 위험이 감지되었습니다. 라이선스 정책을 검토해주세요.")
                
        else:
            st.info("분석 결과가 없습니다. 패키지를 찾을 수 없거나 분석에 실패했을 수 있습니다.")
    
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