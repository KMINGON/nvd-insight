# CVE/CPE/CWE Insight Hub

보안 취약점(CVE), 구성요소(CPE), 약점(CWE) 데이터를 자동으로 수집·정규화하고, 연도별 인사이트 시각화와 RAG 기반 챗봇을 제공하는 Streamlit 애플리케이션입니다. 아래 절차만 따르면 `git clone` 직후에도 동일한 환경에서 바로 실행할 수 있습니다.

## 주요 기능

- **데이터 파이프라인**: NVD/MITRE 원천 데이터를 자동 다운로드 → 정규화 → 연도별 JSON 샤드 생성.
- **RAG 인덱싱**: Sentence-Transformers(기본) 또는 OpenAI 임베딩으로 FAISS 인덱스를 구축하고, LangChain Retriever/LLM으로 질의 응답.
- **Streamlit UI**: 인사이트별(벤더/제품, SKR Score, Published Trend, CVSS 분포, CWE Top-N) 시각화 탭 + RAG 챗봇 탭을 통합 제공.
- **Published Trend 시계열**: 연도/월별 CVE 공개량을 Plotly로 시각화하고 같은 화면에서 계절성 요약 챗봇을 실행.
- **분석/리포트 자산**: `reports/`에 도식/텍스트를 저장하고, 추가 인사이트 모듈을 쉽게 확장할 수 있는 구조.

## 리포지토리 구조 요약

```
data/
├─ raw/          # NVD/MITRE 원본 (CVE/CPE/CWE)
├─ processed/    # 정규화된 연도별 JSON
└─ index/        # RAG 인덱스
docs/            # 스키마/협업 가이드
script/          # 데이터/인덱스/테스트용 CLI 스크립트
src/
├─ dataset/      # load_raw.py + build_dataset.py
├─ analytics/    # Plotly/Altair 차트 & 공통 로더
├─ rag/          # indexer.py + retriever.py
└─ app/          # Streamlit UI/chat 모듈
```

## 사전 요구 사항

- Linux/macOS/WSL 환경 (Windows 네이티브에서도 동작 가능)
- Python **3.10 이상**, `pip`, `git`
- 최소 15GB 디스크 여유(원본 6GB+, 정규화/인덱스 포함)
- (선택) OpenAI API 키 – `EMBEDDING_BACKEND=openai`로 바꿀 경우 필요

## 빠른 시작: 클론부터 Streamlit 실행까지

### 1. 저장소 클론

```bash
git clone https://github.com/KMINGON/nvd-insight.git
cd nvd-insight
```

### 2. 가상환경 생성 & 활성화

```bash
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
```

### 3. 의존성 설치

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **참고**: 최초 실행 시 `sentence-transformers/all-MiniLM-L6-v2` 모델을 자동 다운로드합니다. 방화벽 환경이라면 미리 모델을 캐시하거나 `EMBEDDING_BACKEND=openai`를 사용하세요.

### 4. 원본 데이터 다운로드

```bash
python script/download_data.py
```

- 기본으로 CVE(2020~2025), CPE Dictionary, CWE 카탈로그를 `data/raw/` 하위에 배치합니다.
- 필요한 연도/파일만 수동으로 넣어도 되지만, 디렉터리 구조는 `docs/require_columns.md`에 명시된 규칙을 따라야 합니다.

### 5. 정규화 데이터셋 생성

```bash
python -m src.dataset.build_dataset
```

- 실행이 완료되면 `data/processed/cve_cwe_by_year/cve_cwe_dataset_{YEAR}.json` 파일이 생성됩니다.
- 데이터가 없거나 경로가 잘못되면 `FileNotFoundError`가 발생하므로 4단계를 먼저 수행했는지 확인하세요.

### 6. FAISS 인덱스 구축 (RAG)

```bash
python script/build_faiss_index.py --batch-size 64
```

- 기본 설정: 로컬 Sentence-Transformers 임베딩 + `data/index/faiss/cve_cwe_index/`.
- OpenAI 기반으로 전환하려면 `.env`에 `EMBEDDING_BACKEND=openai`와 `OPENAI_API_KEY`를 설정한 뒤 다시 실행합니다.
- 기존 인덱스를 덮어쓰려면 동일한 명령을 재실행하면 됩니다.

### 7. Streamlit UI 실행

```bash
streamlit run src/app/ui.py
```

- 좌측 사이드바에서 연도/인사이트를 선택하면 시각화 + AI 요약 탭이 표시됩니다.
- RAG 탭이 비활성화될 경우 FAISS 인덱스가 누락된 것이므로 6단계를 재확인하세요.

## 환경 변수(.env) 예시

`.env` 파일은 루트에 위치하며, 없으면 자동으로 무시됩니다.
`.env.example` 파일을 참고하여 작성하세요.

```dotenv
# FAISS 결과를 다른 위치에 저장하고 싶을 때
FAISS_INDEX_DIR=/mnt/data/index_outputs

# OpenAI 백엔드를 사용할 때
EMBEDDING_BACKEND=openai
OPENAI_API_KEY=sk-your-key
CHAT_COMPLETION_MODEL=gpt-4o-mini
```

설정을 변경한 뒤에는 관련 스크립트(예: `build_faiss_index.py`)를 다시 실행해야 적용됩니다.

## 자주 쓰는 스크립트

| 스크립트 | 설명 |
| --- | --- |
| `script/download_data.py` | NVD/MITRE raw 데이터 일괄 다운로드 |
| `python -m src.dataset.build_dataset` | raw → processed 변환 |
| `script/build_faiss_index.py` | 처리된 JSON으로 FAISS 인덱스 생성 |
| `script/data_check.py --year 2024` | 특정 연도의 정규화 데이터를 미리보기 |
| `streamlit run src/app/ui.py` | 웹 UI 실행 |

## 인사이트 확장 가이드

1. `src/analytics/charts/`에 새 모듈을 추가하고 Plotly/Altair Figure 생성 함수를 작성합니다.
2. `src/app/ui.py`의 `INSIGHT_PAGES` 딕셔너리에 새 `InsightPage`를 등록합니다. `render` 콜백에서 시각화 탭과 `streamlit_chat` 탭을 모두 구현하면 기존 구조에 자동으로 연결됩니다.
3. 필요한 경우 RAG 인덱스에 더 많은 메타데이터를 포함시키기 위해 `src/rag/indexer.py`의 `_build_metadata` 함수를 확장합니다.

## 문제 해결

- **FAISS 인덱스가 없다는 경고**: `data/index/faiss/cve_cwe_index/`가 비어 있을 수 있습니다. 6단계를 다시 수행합니다.
- **OpenAI 종속성 오류**: `.env`에 `OPENAI_API_KEY`를 지정했고 `pip install -r requirements.txt`를 완료했는지 확인합니다.
- **Streamlit에서 데이터가 없다고 표시**: `data/processed/cve_cwe_by_year/`가 비어 있으면 5단계를 다시 실행합니다.
- **HuggingFace 모델 다운로드 실패**: 방화벽 환경이라면 VPN/프록시를 사용하거나 수동으로 모델을 다운로드해 `~/.cache/torch/sentence_transformers/`에 배치합니다.

## 참고 문서

- `docs/require_columns.md` – raw 데이터에서 추출하는 필드 정의
- `docs/data_schema_for_analysis.md` – 정규화 결과 스키마
- `docs/analytics_collab_guide.md` – Plotly/Altair 협업 규칙
- `docs/rag_extra_steps.md` – RAG 추가 설정 가이드

---
이전 `README.md`는 `README_v1.md` 이라는 이름으로 기존 참고용으로 그대로 두었습니다.
