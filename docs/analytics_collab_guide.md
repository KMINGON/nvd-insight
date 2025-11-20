# Analytics 협업 가이드

본 문서는 `src/analytics` 폴더에서 여러 팀원이 동시에 시각화를 개발할 때 필요한 공통 규칙을 정리한 가이드입니다. 데이터 로딩 방법, charts 모듈 구조, Streamlit 연동 방식, 각자 수행해야 할 TODO와 산출물을 명확히 정의해 협업 효율을 높입니다.

---

## 1. 작업 흐름 개요

1. **데이터 로딩**  
   - 모든 시각화는 `src/analytics/base_loader.py`의 `load_processed_dataframe()`을 사용해 `data/processed/cve_cwe_by_year/` JSON을 읽습니다.  
   - 필요하면 `--years` 옵션으로 특정 연도만 추출하거나 `--dataset-path`로 샘플 파일을 지정하세요.
2. **차트 구현**  
   - `src/analytics/charts/` 하위에 모듈을 추가하고, `build_*` 형태의 함수를 구현해 pandas DataFrame을 입력으로 받아 Plotly/Altair Figure 객체를 반환합니다.  
   - 함수는 순수하게 Figure만 생성해야 하며, 파일 저장은 하지 않습니다.
3. **테스트 및 공유**  
   - `script/test_load.py`로 로딩이 정상인지 확인한 뒤, 필요 시 `script/test_*_dashboard.py`(예: `test_skr_score_dashboard.py`)로 해당 차트 모듈을 Streamlit 미니앱 형태로 점검합니다.  
   - 메인 멀티페이지 앱(`Home.py` + `pages/*.py`)에서는 `src/app/pages/<feature>.py`가 charts 모듈에서 반환된 Figure/DataFrame을 직접 렌더링합니다.

---

## 2. 데이터 로딩 방법

### 공통 로더 사용
```python
from src.analytics.base_loader import load_processed_dataframe

df = load_processed_dataframe(years=[2023, 2024])
```

- 기본 경로는 `config.PROCESSED_DATASET_DIR`입니다.  
- `years`를 지정하지 않으면 디렉터리 내 모든 연도를 읽습니다.  
- `dataset_path` 매개변수에 단일 JSON 파일 또는 다른 디렉터리를 지정할 수 있습니다.

### 빠른 점검 스크립트
```bash
python3 script/test_load.py --years 2024 --sample 5
python3 script/test_load.py --dataset-path data/processed/cve_cwe_by_year/cve_cwe_dataset_2023.json
```

출력 내용:
- 레코드 수, 컬럼 수, dtype 일부
- 상위 레코드의 기본 정보(`cveId`, `published`, `description`)
- `cpes` / `cwes` 리스트 길이 요약  
이 정보를 참고해 컬럼 존재 여부와 데이터 포맷을 확인한 뒤 차트 작성에 착수합니다.

---

## 3. charts 모듈 작성 규칙

| 항목 | 규칙 |
| --- | --- |
| 파일 위치 | `src/analytics/charts/<주제>.py` (`analysis_example.py` 또는 기존 모듈 참고) |
| 함수 시그니처 예시 | `def build_high_risk_vendor_chart(df: pd.DataFrame, top_n: int = 15) -> Figure:` |
| 반환값 | Plotly Figure (`plotly.graph_objects.Figure` 또는 `plotly.io.Figure`), 혹은 Altair Chart |
| I/O | 함수 내부에서 파일 저장 금지. 저장/다운로드는 Streamlit 측(`src/app/pages` 또는 `pages/*.py`)에서 처리 |
| 주석/TODO | 복잡한 전처리나 향후 확장을 위해 주석·TODO를 남겨 협업 시 혼선을 줄입니다. |

모듈을 추가한 뒤 `src/analytics/charts/__init__.py`에 `__all__`을 업데이트해 다른 부분에서 쉽게 import 할 수 있도록 하세요. 예시 구현(`analysis_example.py`)처럼, 필요한 경우 보조 함수(예: `summarize_*`)도 같은 파일에 함께 두고 재사용할 수 있습니다.

---

## 4. TODO 및 산출물 예시

다음 작업들은 팀원이 나누어 맡을 수 있는 대표적인 TODO 목록입니다. 각 작업은 기본적으로 **Figure 객체**(Streamlit 렌더링용) 혹은 **pandas DataFrame**(필요 시)을 산출물로 제공합니다.

1. **벤더/제품 Top-N (예: `vendor_product_chart.py`)**
   - 입력: `df`, `top_n`, 필터 옵션
   - 산출물: Plotly 수평 막대 그래프 2종 + 요약 DataFrame
2. **SKR Score/고위험 지표 (`skr_score.py`)**
   - 입력: 정규화 DF, 점수 임계값
   - 산출물: Top10 막대, 벤더/제품/CWE 테이블
3. **시계열/트렌드 (`published_trend_app.py`, `cvss.py`)**
   - 입력: 날짜 컬럼/metric 설정
   - 산출물: 연월 추이, Heatmap, CVSS Severity/Score 분포
4. **기타 메트릭**
   - 새로운 조합(CISA 플래그, 평균 공개 지연 등)을 정의하고 동일한 패턴으로 `build_*` 함수를 추가

각 TODO는 최소한 다음 요소를 포함해야 합니다.
- 입력 파라미터와 기본값 (예: `top_n`, `year_filters`, `severity_levels`)
- 반환 Figure의 제목/축/범례 설정
- Streamlit에서 바로 사용 가능한 형태 (`st.plotly_chart(fig)`)

---

## 5. 산출물 공유 및 품질 체크

1. **브랜치 규칙**  
   - 차트별 or 기능별 브랜치 생성 → PR 작성 시 `streamlit run script/test_<chart>_dashboard.py` 실행 화면 또는 스크린샷을 첨부하세요.
2. **테스트**  
   - `script/test_load.py`로 데이터 포맷 확인 후, 필요하면 차트별 테스트 스크립트로 Plotly 렌더링 여부를 확인합니다.
3. **문서화**  
   - 새 차트를 추가했으면 README 또는 `docs/` 산출물에 해당 기능을 언급하고, `pages/*.py`에서 탭/설명 문구를 업데이트합니다.

---

## 6. 참고 링크

- [README.md](../README.md) – 프로젝트 전반 구조 및 세팅
- [docs/data_schema_for_analysis.md](data_schema_for_analysis.md) – 정규화 데이터 스키마
- [docs/require_columns.md](require_columns.md) – 원본 컬럼 추출 기준
- [script/test_load.py](../script/test_load.py) – 로더 확인 스크립트
