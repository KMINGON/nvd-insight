```text
cve_project/
├─ Home.py                     # Streamlit 멀티페이지 엔트리포인트
├─ pages/                      # Streamlit 페이지 셸 (src/app/pages 레이아웃 호출)
│  ├─ 01_Vendor_Product.py
│  ├─ 02_SKR_Score.py
│  ├─ 03_Published_Trend.py
│  ├─ 04_CVSS_Distribution.py
│  └─ 05_CWE_TopN.py
├─ data/
│  ├─ raw/                     # download_data.py가 내려받은 NVD/MITRE 원본
│  │  ├─ cve/                  # nvdcve-2.0-<year>.json
│  │  ├─ cpe/                  # CPE Dictionary chunk JSON
│  │  └─ cwe/                  # cwec_v4.18.xml
│  ├─ processed/
│  │  └─ cve_cwe_by_year/      # build_dataset.py 결과 (연도별 JSON 샤드)
│  └─ index/
│     └─ faiss/                # VectorIndexer가 저장한 인덱스 폴더
├─ docs/                       # 발표/요구사항/데이터 스키마 문서
├─ script/                     # CLI 유틸 (데이터 다운로드, 인덱스 빌드, 테스트 등)
│  ├─ download_data.py
│  ├─ build_faiss_index.py
│  ├─ data_check.py
│  ├─ test_load.py
│  └─ test_*_dashboard.py      # Streamlit 차트 스모크 테스트
├─ reports/
│  └─ text/                    # rag_report.py가 생성한 텍스트 리포트
├─ src/
│  ├─ config.py                # 경로/임베딩/환경 변수 설정
│  ├─ dataset/
│  │  ├─ load_raw.py          # 원본 CVE/CPE/CWE 로더
│  │  └─ build_dataset.py     # 정규화 + 연도별 JSON 생성
│  ├─ analytics/
│  │  ├─ base_loader.py       # processed JSON → pandas 변환
│  │  ├─ charts/              # Plotly/Altair 차트 모듈 (vendor, SKR 등)
│  │  └─ rag_report.py        # RAG 기반 텍스트 리포트 헬퍼
│  ├─ rag/
│  │  ├─ indexer.py           # processed JSON → FAISS 인덱스
│  │  └─ retriever.py         # 필터링 + LLM 요약
│  └─ app/
│     ├─ common.py            # Streamlit 세션/데이터/RAG 공유 유틸
│     ├─ chat.py              # AnalysisChatService + streamlit_chat
│     └─ pages/               # 실제 렌더 함수(render_*_page)
├─ requirements.txt
└─ README.md
```
