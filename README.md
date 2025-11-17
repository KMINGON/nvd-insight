## 디렉터리 개요

```
data/
├─ raw/          # 주어진 원본 데이터 (기존 유지)
├─ processed/    # build_dataset.py 실행 결과
└─ index/        # RAG용 인덱스 산출 위치
reports/
├─ figures/      # 시각화 결과물
└─ text/         # RAG 기반 리포트 초안
src/
├─ config.py
├─ dataset/
│  ├─ load_raw.py
│  └─ build_dataset.py
├─ analytics/
│  ├─ viz.py
│  └─ rag_report.py
├─ rag/
│  ├─ indexer.py
│  └─ retriever.py
└─ app/
   ├─ ui.py
   └─ chat.py
```

## 주요 스크립트

- `src/dataset/load_raw.py`  
  - `load_cve_records`, `load_cpe_dictionary`, `load_cwe_catalog` 함수를 통해 `/docs/require_columns.md`에 정의된 컬럼만 불러옵니다.
- `src/dataset/build_dataset.py`  
  - 위의 로더 결과를 `/docs/data_schema_for_analysis.md` 구조에 맞추어 가공하여 `data/processed/cve_cwe_dataset.json`으로 저장합니다.

두 모듈 모두 단독 실행이 가능하도록 `__main__` 블록을 포함하고 있습니다.

## 정규화된 데이터 개요

- 경로: `data/processed/cve_cwe_by_year/cve_cwe_dataset_{YYYY}.json`
- 레코드 수: 연도별로 분리 저장 (2020~2025 기준 총 173,480개 CVE)
- 주요 필드
  - `cveId`, `published`, `lastModified`, `description`
  - `metrics`: NVD의 CVSS 세부 점수(JSON 구조 유지)
  - `cpes`: CVE 구성 정보와 CPE Dictionary 조인 결과 (제품 메타 포함)
  - `cwes`: CWE 카탈로그에서 확장 설명/배경을 매핑한 리스트

데이터 내용을 빠르게 확인하고 싶다면 `script/data_check.py` 스크립트를 사용하면 된다. 이 스크립트는 상위 N개의 CVE 레코드를 순회하며 중첩 구조의 모든 컬럼을 들여쓰기를 적용해 출력한다(리스트 항목 수가 많을 경우 처음 몇 개만 표시 + 나머지 개수 안내). `pandas`가 설치되어 있을 경우 테이블 형태 미리보기/기본 통계도 함께 보여준다.

```bash
python3 script/data_check.py --year 2024              # 2024년 데이터 기준 기본 5건 출력
python3 script/data_check.py --year 2021 --top-n 3    # 상위 3건만 상세 보기
python3 script/data_check.py --file ./path/custom.json
```

또한 `script/download_data.py`를 실행하면 NVD·MITRE에서 CVE/CPE/CWE 원본을 자동으로 내려받아 `data/raw/` 구조에 맞게 배치한다.

```bash
python3 script/download_data.py          # 기본 2020~2025 CVE + CPE Dictionary + CWE
python3 script/download_data.py --help   # (필요 시 옵션 추가 예정)
```

## 사용 방법

1. **원본 데이터 다운로드 (선택)**
   - 처음 세팅하거나 최신 NVD/MITRE 데이터를 받고 싶다면:
     ```bash
     python3 script/download_data.py    # CVE(2020~2025), CPE Dictionary, CWE
     ```
     네트워크 제약이 있는 환경이면 파일을 수동으로 `data/raw/` 위치에 배치해도 된다.

2. **가상환경 생성 및 의존성 설치**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. **데이터 가공**
   ```bash
   python -m src.dataset.build_dataset
   ```
   - 실행 후 `data/processed/cve_cwe_by_year/` 하위에 연도별 JSON이 생성됩니다.
4. **후속 작업**
   - `src/analytics/viz.py`의 TODO를 채우면 pandas/plotly 기반 분석 스크립트를 완성할 수 있습니다.
   - `src/rag/`와 `src/app/` 모듈의 TODO를 구현하면 FAISS + LangChain 기반 인덱싱 및 Streamlit UI를 구축할 수 있습니다.

## 참고 문서

- `/docs/require_columns.md` – raw 데이터에서 추출하는 컬럼 설명
- `/docs/data_schema_for_analysis.md` – 분석용 최종 데이터 스키마
