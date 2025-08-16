# SBOM Analysis Module - analysis.py

import os
import json
import tempfile
import shutil
import subprocess
import pandas as pd
from typing import Tuple, Dict, Any
from urllib.parse import urlparse
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_required_tools() -> Dict[str, str]:
    """
    필수 도구들이 시스템에 설치되어 있는지 확인합니다.
    
    Returns:
        Dict[str, str]: 도구 이름과 경로 매핑
        
    Raises:
        FileNotFoundError: 필수 도구가 없을 경우
    """
    required_tools = {
        'git': 'Git',
        'syft': 'Syft',
        'osv-scanner': 'OSV-Scanner'
    }
    
    tool_paths = {}
    missing_tools = []
    
    for tool_cmd, tool_name in required_tools.items():
        tool_path = shutil.which(tool_cmd)
        if tool_path is None:
            missing_tools.append(tool_name)
            logger.error(f"{tool_name} 실행 파일을 찾을 수 없습니다.")
        else:
            tool_paths[tool_cmd] = tool_path
            logger.info(f"{tool_name} 발견: {tool_path}")
    
    if missing_tools:
        error_msg = f"다음 프로그램이 설치되지 않았습니다: {', '.join(missing_tools)}\n"
        error_msg += "각 도구가 설치되어 있고, 시스템 PATH에 등록되어 있는지 확인해주세요.\n\n"
        error_msg += "설치 방법:\n"
        
        if 'Git' in missing_tools:
            error_msg += "- Git: https://git-scm.com/downloads\n"
        if 'Syft' in missing_tools:
            error_msg += "- Syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin\n"
        if 'OSV-Scanner' in missing_tools:
            error_msg += "- OSV-Scanner: go install github.com/google/osv-scanner/cmd/osv-scanner@latest\n"
        
        raise FileNotFoundError(error_msg)
    
    return tool_paths

def analyze_project(target_path: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Python 프로젝트의 SBOM을 생성하고 취약점을 분석합니다.
    
    Args:
        target_path (str): Git URL 또는 로컬 폴더 경로
        
    Returns:
        Tuple[pd.DataFrame, Dict]: 분석 결과 DataFrame과 요약 정보 Dictionary
    """
    
    temp_dir = None
    analysis_path = None
    
    try:
        # 필수 도구 확인
        logger.info("필수 도구 확인 중...")
        tool_paths = check_required_tools()
        
        # 1. 입력 처리 - URL인지 로컬 경로인지 확인
        if is_git_url(target_path):
            logger.info(f"Git URL 감지: {target_path}")
            temp_dir = tempfile.mkdtemp(prefix="sbom_analysis_")
            analysis_path = clone_git_repo(target_path, temp_dir, tool_paths['git'])
        else:
            # 로컬 경로 확인
            if not os.path.exists(target_path):
                raise FileNotFoundError(f"경로를 찾을 수 없습니다: {target_path}")
            if not os.path.isdir(target_path):
                raise NotADirectoryError(f"디렉토리가 아닙니다: {target_path}")
            logger.info(f"로컬 경로 사용: {target_path}")
            analysis_path = target_path
        
        # 2. SBOM 생성
        logger.info("SBOM 생성 중...")
        sbom_path = generate_sbom(analysis_path, tool_paths['syft'])
        
        # 3. 취약점 스캔
        logger.info("취약점 스캔 중...")
        vuln_path = scan_vulnerabilities(sbom_path, tool_paths['osv-scanner'])
        
        # 4. 결과 파싱 및 데이터프레임 생성
        logger.info("결과 분석 중...")
        df, summary = parse_results(sbom_path, vuln_path)
        
        return df, summary
        
    except FileNotFoundError as e:
        # 파일이나 도구를 찾을 수 없는 경우
        logger.error(f"파일 또는 도구 오류: {str(e)}")
        empty_df = pd.DataFrame(columns=['Package', 'Version', 'License', 
                                        'License Risk', 'Vulnerabilities', 
                                        'Highest Severity'])
        error_summary = {
            'total_packages': 0,
            'vulnerabilities_found': 0,
            'license_risks': 0,
            'error': str(e)
        }
        return empty_df, error_summary
        
    except subprocess.CalledProcessError as e:
        # 명령어 실행 실패
        logger.error(f"명령어 실행 실패: {str(e)}")
        error_msg = f"명령어 실행 중 오류 발생: {e.cmd}\n"
        if e.stderr:
            error_msg += f"에러 메시지: {e.stderr}"
        
        empty_df = pd.DataFrame(columns=['Package', 'Version', 'License', 
                                        'License Risk', 'Vulnerabilities', 
                                        'Highest Severity'])
        error_summary = {
            'total_packages': 0,
            'vulnerabilities_found': 0,
            'license_risks': 0,
            'error': error_msg
        }
        return empty_df, error_summary
        
    except Exception as e:
        logger.error(f"분석 중 오류 발생: {str(e)}")
        empty_df = pd.DataFrame(columns=['Package', 'Version', 'License', 
                                        'License Risk', 'Vulnerabilities', 
                                        'Highest Severity'])
        error_summary = {
            'total_packages': 0,
            'vulnerabilities_found': 0,
            'license_risks': 0,
            'error': str(e)
        }
        return empty_df, error_summary
        
    finally:
        # 임시 디렉토리 정리
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.info("임시 디렉토리 정리 완료")
            except Exception as e:
                logger.warning(f"임시 디렉토리 정리 실패: {str(e)}")

def is_git_url(path: str) -> bool:
    """
    주어진 경로가 Git URL인지 확인합니다.
    """
    try:
        result = urlparse(path)
        return all([result.scheme, result.netloc]) and \
               (path.endswith('.git') or 'github.com' in path or 'gitlab.com' in path)
    except:
        return False

def clone_git_repo(url: str, target_dir: str, git_path: str) -> str:
    """
    Git repository를 클론합니다.
    
    Args:
        url (str): Git repository URL
        target_dir (str): 대상 디렉토리
        git_path (str): Git 실행 파일 경로
        
    Returns:
        str: 클론된 repository 경로
        
    Raises:
        subprocess.CalledProcessError: Git 클론 실패 시
    """
    repo_dir = os.path.join(target_dir, "repo")
    logger.info(f"Git 클론 시작: {url} -> {repo_dir}")
    
    # Git 명령어 실행 (shell=True 사용하지 않음)
    cmd = [git_path, "clone", "--depth", "1", url, repo_dir]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True  # 실패 시 CalledProcessError 발생
        )
        logger.info("Git 클론 완료")
        return repo_dir
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Git 클론 실패\n명령어: {' '.join(cmd)}\n"
        if e.stderr:
            error_msg += f"에러: {e.stderr}"
        logger.error(error_msg)
        raise subprocess.CalledProcessError(e.returncode, cmd, output=e.stdout, stderr=error_msg)

def generate_sbom(project_path: str, syft_path: str) -> str:
    """
    Syft를 사용하여 SBOM을 생성합니다.
    
    Args:
        project_path (str): 프로젝트 경로
        syft_path (str): Syft 실행 파일 경로
        
    Returns:
        str: 생성된 SBOM 파일 경로
        
    Raises:
        subprocess.CalledProcessError: SBOM 생성 실패 시
    """
    # SBOM 출력 파일 경로
    sbom_path = os.path.join(tempfile.gettempdir(), "sbom.json")
    
    # Syft 명령어 구성 (shell=True 사용하지 않음)
    cmd = [
        syft_path,
        "packages",
        f"dir:{project_path}",
        "-o",
        f"cyclonedx-json={sbom_path}"
    ]
    
    logger.info(f"Syft 실행 중: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True  # 실패 시 CalledProcessError 발생
        )
        
        if not os.path.exists(sbom_path):
            raise FileNotFoundError(f"SBOM 파일이 생성되지 않았습니다: {sbom_path}")
        
        # SBOM 파일 크기 확인
        file_size = os.path.getsize(sbom_path)
        if file_size == 0:
            raise ValueError("SBOM 파일이 비어있습니다.")
        
        logger.info(f"SBOM 생성 완료: {sbom_path} (크기: {file_size} bytes)")
        return sbom_path
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Syft 실행 실패\n명령어: {' '.join(cmd)}\n"
        if e.stderr:
            error_msg += f"에러: {e.stderr}"
        logger.error(error_msg)
        
        # Fallback 메커니즘 시도
        logger.info("Fallback SBOM 생성 시도...")
        return generate_fallback_sbom(project_path)

def generate_fallback_sbom(project_path: str) -> str:
    """
    Syft를 사용할 수 없을 때 requirements.txt를 기반으로 간단한 SBOM을 생성합니다.
    """
    logger.info("대체 SBOM 생성 방법 사용 중...")
    
    sbom_path = os.path.join(tempfile.gettempdir(), "sbom.json")
    packages = []
    
    # requirements.txt 파일 찾기
    req_files = ['requirements.txt', 'requirements.pip', 'requirements.in', 'Pipfile', 'pyproject.toml']
    found_req_file = False
    
    for req_file in req_files:
        req_path = os.path.join(project_path, req_file)
        if os.path.exists(req_path):
            found_req_file = True
            logger.info(f"의존성 파일 발견: {req_file}")
            
            with open(req_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 패키지명과 버전 파싱
                        package_info = parse_package_line(line)
                        if package_info:
                            packages.append(package_info)
    
    if not found_req_file:
        logger.warning("의존성 파일을 찾을 수 없습니다.")
    
    # 간단한 SBOM 구조 생성
    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": packages
    }
    
    with open(sbom_path, 'w', encoding='utf-8') as f:
        json.dump(sbom_data, f, indent=2)
    
    logger.info(f"대체 SBOM 생성 완료: {sbom_path} ({len(packages)}개 패키지)")
    return sbom_path

def parse_package_line(line: str) -> Dict[str, str]:
    """
    requirements.txt의 한 줄을 파싱하여 패키지 정보를 추출합니다.
    """
    # 다양한 형식 지원
    if '==' in line:
        parts = line.split('==')
        return {"name": parts[0].strip(), "version": parts[1].strip(), "type": "python"}
    elif '>=' in line:
        parts = line.split('>=')
        return {"name": parts[0].strip(), "version": f">={parts[1].strip()}", "type": "python"}
    elif '<=' in line:
        parts = line.split('<=')
        return {"name": parts[0].strip(), "version": f"<={parts[1].strip()}", "type": "python"}
    elif '~=' in line:
        parts = line.split('~=')
        return {"name": parts[0].strip(), "version": f"~={parts[1].strip()}", "type": "python"}
    else:
        # 버전이 명시되지 않은 경우
        name = line.split('[')[0].strip()
        if name:
            return {"name": name, "version": "unknown", "type": "python"}
    return None

def scan_vulnerabilities(sbom_path: str, osv_scanner_path: str) -> str:
    """
    OSV-Scanner를 사용하여 취약점을 스캔합니다.
    
    Args:
        sbom_path (str): SBOM 파일 경로
        osv_scanner_path (str): OSV-Scanner 실행 파일 경로
        
    Returns:
        str: 취약점 스캔 결과 파일 경로
    """
    vuln_path = os.path.join(tempfile.gettempdir(), "vulnerabilities.json")
    
    # OSV-Scanner 명령어 구성 (shell=True 사용하지 않음)
    cmd = [
        osv_scanner_path,
        f"--sbom={sbom_path}",
        "--format=json"
    ]
    
    logger.info(f"OSV-Scanner 실행 중: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False  # OSV-Scanner는 취약점 발견 시 exitcode 1 반환
        )
        
        # OSV-Scanner는 취약점이 있으면 exitcode 1, 없으면 0 반환
        if result.returncode not in [0, 1]:
            error_msg = f"OSV-Scanner 실행 실패 (exitcode: {result.returncode})\n"
            if result.stderr:
                error_msg += f"에러: {result.stderr}"
            logger.error(error_msg)
            # 빈 결과 생성
            with open(vuln_path, 'w', encoding='utf-8') as f:
                f.write(json.dumps({"results": []}))
        else:
            # 정상 실행 - 결과를 파일로 저장
            with open(vuln_path, 'w', encoding='utf-8') as f:
                if result.stdout:
                    f.write(result.stdout)
                else:
                    f.write(json.dumps({"results": []}))
            
            if result.returncode == 1:
                logger.warning("취약점이 발견되었습니다.")
            else:
                logger.info("취약점이 발견되지 않았습니다.")
        
        logger.info(f"취약점 스캔 완료: {vuln_path}")
        return vuln_path
        
    except Exception as e:
        logger.error(f"취약점 스캔 중 오류: {str(e)}")
        # 에러 발생 시에도 빈 결과 파일 생성
        with open(vuln_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps({"results": []}))
        return vuln_path

def parse_results(sbom_path: str, vuln_path: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    SBOM과 취약점 스캔 결과를 파싱하여 DataFrame과 요약 정보를 생성합니다.
    """
    try:
        # SBOM 파일 읽기
        with open(sbom_path, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
        
        # 취약점 파일 읽기
        with open(vuln_path, 'r', encoding='utf-8') as f:
            vuln_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"JSON 파싱 오류: {str(e)}")
        return pd.DataFrame(), {'total_packages': 0, 'vulnerabilities_found': 0, 'license_risks': 0}
    
    # 패키지 정보 추출
    packages = []
    
    # SBOM에서 컴포넌트 정보 추출
    components = sbom_data.get('components', [])
    
    # 취약점 정보를 패키지별로 매핑
    vuln_map = {}
    if 'results' in vuln_data:
        for result in vuln_data['results']:
            for package in result.get('packages', []):
                pkg_info = package.get('package', {})
                pkg_name = pkg_info.get('name', '')
                vulns = package.get('vulnerabilities', [])
                if pkg_name and vulns:
                    vuln_map[pkg_name] = vulns
    
    # 각 컴포넌트에 대해 정보 수집
    for component in components:
        name = component.get('name', 'Unknown')
        version = component.get('version', 'Unknown')
        
        # 라이선스 정보 추출
        licenses = component.get('licenses', [])
        if licenses:
            license_info = licenses[0].get('license', {})
            license_name = license_info.get('name', license_info.get('id', 'Unknown'))
        else:
            license_name = 'Unknown'
        
        # 라이선스 위험도 평가
        license_risk = evaluate_license_risk(license_name)
        
        # 취약점 정보
        vulns = vuln_map.get(name, [])
        vuln_count = len(vulns)
        
        # 가장 높은 심각도 찾기
        highest_severity = 'N/A'
        if vulns:
            severities = []
            for vuln in vulns:
                # 다양한 위치에서 severity 찾기
                severity = (vuln.get('database_specific', {}).get('severity') or
                          vuln.get('severity') or
                          vuln.get('cvss_v3', {}).get('severity') or
                          'UNKNOWN')
                severities.append(severity.upper())
            
            # 심각도 우선순위
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            for sev in severity_order:
                if sev in severities:
                    highest_severity = sev.capitalize()
                    break
        
        packages.append({
            'Package': name,
            'Version': version,
            'License': license_name,
            'License Risk': license_risk,
            'Vulnerabilities': vuln_count,
            'Highest Severity': highest_severity
        })
    
    # DataFrame 생성
    df = pd.DataFrame(packages)
    
    # 빈 DataFrame 처리
    if df.empty:
        df = pd.DataFrame(columns=['Package', 'Version', 'License', 
                                  'License Risk', 'Vulnerabilities', 
                                  'Highest Severity'])
    
    # 요약 정보 생성
    summary = {
        'total_packages': len(df),
        'vulnerabilities_found': int(df['Vulnerabilities'].sum()) if not df.empty else 0,
        'license_risks': len(df[df['License Risk'].isin(['높음', '중간'])]) if not df.empty else 0
    }
    
    logger.info(f"분석 완료: {summary['total_packages']}개 패키지, "
               f"{summary['vulnerabilities_found']}개 취약점 발견")
    
    return df, summary

def evaluate_license_risk(license_name: str) -> str:
    """
    라이선스 위험도를 평가합니다.
    """
    if not license_name:
        return '확인필요'
    
    license_lower = license_name.lower()
    
    # 높은 위험도 라이선스 (Copyleft)
    high_risk = ['gpl', 'agpl', 'lgpl', 'mpl', 'eupl', 'osl', 'afl']
    
    # 중간 위험도 라이선스
    medium_risk = ['apache', 'eclipse', 'cddl', 'artistic']
    
    # 낮은 위험도 라이선스
    low_risk = ['mit', 'bsd', 'isc', 'unlicense', 'cc0', 'wtfpl', 'zlib', 'x11']
    
    for risk in high_risk:
        if risk in license_lower:
            return '높음'
    
    for risk in medium_risk:
        if risk in license_lower:
            return '중간'
    
    for risk in low_risk:
        if risk in license_lower:
            return '낮음'
    
    if 'unknown' in license_lower or license_lower == 'unknown':
        return '확인필요'
    
    # 알 수 없는 라이선스는 중간 위험으로 분류
    return '중간'