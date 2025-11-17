## phase 1
### 디렉토리 구조 생성
```text
cve_cwe_mini/
├─ data/
│  ├─ raw/          # 원본 CVE/CWE 데이터 (NVD JSON 등)
│  ├─ processed/    # 컬럼 추출 후 json 데이터셋
│  └─ index/        # RAG용 벡터 인덱스/메타데이터 파일
├─ reports/
│  ├─ figures/      # 시각화 결과 png 등
│  └─ text/         # RAG 기반 리포트 텍스트
├─ src/
│  ├─ config.py
│  ├─ dataset/
│  │  ├─ __init__.py
│  │  ├─ load_raw.py        # CVE/CWE 원본 로딩
│  │  └─ build_dataset.py   # 컬럼 추출, json 생성
│  ├─ analytics/
│  │  ├─ __init__.py
│  │  ├─ viz.py             # pandas + 시각화 함수
│  │  └─ rag_report.py      # RAG 활용 리포트 생성
│  ├─ rag/
│  │  ├─ __init__.py
│  │  ├─ indexer.py         # 임베딩 생성 + 인덱스 저장
│  │  └─ retriever.py       # 질의 → 유사 도큐먼트 반환
│  └─ app/
│     ├─ __init__.py
│     ├─ ui.py              # streamlit 메인 앱
│     └─ chat.py            # RAG 기반 QA 챗봇 로직
├─ requirements.txt
└─ README.md
```
### load_raw.py 구현
- cve, cpe dictionary, cwe 파일에서 각각 '/docs/require_columns.md' 에 정의된 대로 필요한 컬럼만 뽑아서 데이터 로드

### build_dataset.py 구현
- load_raw.py 에서 로드한 데이터를 '/docs/data_schema_for_analysis.md' 에 정의된 구조에 맞게 매핑하여 'data/processed/' 에 json 파일로 저장

## phase 2
### 스켈레톤 코드 추가
- pandas, streamlit, FAISS, langchain 기반 데이터 분석 시각화 및 RAG 기반 분석 결과 리포트 생성 및 사용자 질의 챗봇 기능을 담당하는 코드 파일들의 기본 뼈대 코드 를 -TODO 형식으로 예시를 주어 작성