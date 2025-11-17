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