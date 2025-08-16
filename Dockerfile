# 1. 베이스 이미지 선택: Python 3.10 버전이 설치된 가벼운 리눅스(Debian)로 시작합니다.
FROM python:3.11-slim

# 2. 작업 폴더 설정: 컨테이너 내부에 /app 이라는 폴더를 만들고, 앞으로 모든 작업은 여기서 진행합니다.
WORKDIR /app

# 3. 필수 도구 설치: Git, Go(OSV-Scanner 설치용), Syft, OSV-Scanner를 설치합니다.
# apt-get update로 패키지 목록을 최신화하고, 필요한 도구들을 설치합니다.
# &&는 여러 명령을 한 줄에서 실행하게 해줍니다.
RUN apt-get update && apt-get install -y \
    git \
    curl \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Syft 설치 (사용자가 제공한 공식 설치 스크립트 사용)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# OSV-Scanner 설치 (Go를 이용해 설치)
# Go로 설치된 프로그램은 /root/go/bin 폴더에 저장되므로, 이 경로를 환경변수 PATH에 추가해줍니다.
ENV PATH="/root/go/bin:${PATH}"
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# 4. Python 라이브러리 설치: 먼저 requirements.txt 파일만 복사합니다.
# (이렇게 하면 나중에 코드만 바뀔 때 이 단계는 다시 실행하지 않아 더 빠릅니다.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 프로젝트 코드 복사: 현재 폴더의 모든 파일(Dockerfile, .dockerignore 제외)을 컨테이너의 /app 폴더로 복사합니다.
COPY . .

# 6. 포트 개방: Streamlit의 기본 포트인 8501번을 외부에 노출하도록 설정합니다.
EXPOSE 8501

# 7. 애플리케이션 실행: 컨테이너가 시작될 때 자동으로 실행할 명령어를 지정합니다. (app.py는 메인 파일명으로 가정)
CMD ["streamlit", "run", "main.py"]