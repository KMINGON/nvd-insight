from __future__ import annotations  # 향후 버전의 타입 힌트 기능(예: | 문법)을 사용할 수 있게 함

from typing import Sequence  # 시퀀스 타입(리스트, 튜플 등)을 타입 힌트로 사용하기 위해 import

import pandas as pd  # 데이터 처리/분석 라이브러리
import plotly.express as px  # Plotly의 간단한 인터페이스
from plotly.graph_objects import Figure  # 반환 타입으로 사용할 Plotly Figure 클래스

# CVSS severity 순서를 고정하기 위한 상수
# → 시각화 시 축 정렬을 일정하게 유지하기 위해 사용 (LOW → CRITICAL)
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# CVSS baseScore에 대해 기본으로 사용할 구간(bin) 경계값
# → 0–3, 3–6, 6–8, 8–10 네 구간으로 나누기 위함
DEFAULT_SCORE_BINS: tuple[float, ...] = (0, 3, 6, 8, 10)


def extract_cvss_metrics(df: pd.DataFrame, metric_col: str = "metrics.cvssMetricV31") -> pd.DataFrame:
    """
    Explode a CVSS metric list column and project baseScore/baseSeverity.

    이 함수의 역할:
    - DataFrame 내부의 CVSS 메트릭 컬럼(예: metrics.cvssMetricV31)을 받아서
      1) 리스트 형태(여러 메트릭)로 들어있는 것을 행 단위로 펼치고(explode),
      2) JSON 형태의 구조를 평탄화(normalize)한 뒤,
      3) baseScore와 baseSeverity만 추출한 '평평한' DataFrame으로 변환한다.

    사용 이유:
    - NVD JSON 스키마에서는 CVSS 정보가 리스트 + 중첩 JSON 형태로 들어있어서
      시각화/집계에 바로 쓰기 어렵다.
    - 시각화 함수(build_cvss_severity_chart, build_cvss_score_bin_chart)에서
      공통으로 사용할 수 있는 전처리 단계로 분리해 재사용성을 높인다.
    """
    # 지정한 metric_col이 DataFrame에 없으면, 데이터 정규화 과정이 잘못된 것이므로 에러를 발생시킨다.
    if metric_col not in df.columns:
        raise ValueError(f"{metric_col} column missing; confirm dataset normalization")

    # metric_col은 보통 리스트(여러 메트릭) 형태이므로 explode()로 행 단위로 펼친다.
    # dropna()로 None/NaN 값은 제거한다.
    exploded = df[metric_col].explode().dropna()
    if exploded.empty:
        # 펼쳤을 때 아무 메트릭도 없다면, 해당 컬럼에 유효한 CVSS 메트릭이 없는 것으로 판단.
        raise ValueError(f"No CVSS metrics found in {metric_col}")

    # json_normalize를 사용해서 중첩된 JSON 구조를 "평평한" 컬럼 구조로 변환한다.
    normalized = pd.json_normalize(exploded)

    # CVSS 메트릭에서 baseScore는 항상 cvssData.baseScore 아래에 존재해야 한다.
    if "cvssData.baseScore" not in normalized.columns:
        raise ValueError("cvssData.baseScore missing in CVSS metrics payload")

    # baseSeverity 위치는 스키마/버전에 따라 다를 수 있으므로 두 위치를 모두 고려한다.
    # 1) 최상위 컬럼 baseSeverity
    # 2) cvssData.baseSeverity (혹시 여기에 들어있는 경우)
    severity_col = (
        normalized["baseSeverity"]
        if "baseSeverity" in normalized.columns
        else normalized.get("cvssData.baseSeverity")
    )

    # 우리가 최종적으로 사용할 컬럼만 추출해서 subset DataFrame 생성:
    # - baseScore: cvssData.baseScore에서 가져온 수치형 점수
    # - baseSeverity: 심각도(LOW / MEDIUM / HIGH / CRITICAL 등)
    subset = pd.DataFrame(
        {
            "baseScore": normalized["cvssData.baseScore"],
            "baseSeverity": severity_col,
        }
    )

    # baseSeverity를 일관된 문자열 대문자로 통일해서, 나중에 value_counts 등에서 혼동을 줄인다.
    subset["baseSeverity"] = subset["baseSeverity"].astype(str).str.upper()

    # baseScore가 없는 행은 분석 대상에서 제외한다.
    # (score가 없는 메트릭은 전염성/위험도를 산출할 수 없다고 판단)
    return subset.dropna(subset=["baseScore"])


def build_cvss_severity_chart(
    df: pd.DataFrame,
    *,
    metric_col: str = "metrics.cvssMetricV31",
    title: str | None = None,
) -> Figure:
    """
    CVSS baseSeverity 분포를 막대 그래프로 그리는 함수.

    동작 개요:
    1. extract_cvss_metrics()를 통해 주어진 metric_col에서 baseScore/baseSeverity를 추출한다.
    2. baseSeverity 값들을 집계하여 각 severity 수준별 개수를 계산한다.
    3. SEVERITY_ORDER 순서에 맞춰 재정렬하여 시각적으로 일관된 순서를 유지한다.
    4. Plotly의 bar 차트를 사용해 결과를 시각화해서 Figure 객체로 반환한다.

    활용 시나리오:
    - 데이터셋 전체에서 HIGH/CRITICAL 비중이 어느 정도인지 한눈에 파악하고 싶을 때
    - CVSS v3.1와 v2의 severity 분포를 비교 시각화할 때
    """
    # 1) CVSS 메트릭에서 baseScore/baseSeverity 추출
    metrics_df = extract_cvss_metrics(df, metric_col=metric_col)

    # 2) baseSeverity별 개수 계산
    counts = metrics_df["baseSeverity"].value_counts()

    # 3) SEVERITY_ORDER 순서에 맞춰 재정렬하고, 존재하지 않는 항목은 0으로 채운다.
    counts = counts.reindex(SEVERITY_ORDER, fill_value=0)

    # 4) Plotly에 넣기 쉽도록 DataFrame 형태로 변환
    summary = counts.rename_axis("baseSeverity").reset_index(name="count")

    # 5) 막대 그래프 생성
    fig = px.bar(
        summary,
        x="baseSeverity",  # x축: severity 레벨
        y="count",         # y축: 개수
        category_orders={"baseSeverity": SEVERITY_ORDER},  # 시각화 순서를 LOW→CRITICAL로 고정
        labels={"baseSeverity": "Base Severity", "count": "Count"},  # 축 레이블
        title=title or f"CVSS severity distribution ({metric_col})",  # 제목 (컬럼명 정보 포함)
    )

    # 6) 레이아웃 여백을 약간 조정해서 보기 좋게 정리
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


def build_cvss_score_bin_chart(
    df: pd.DataFrame,
    *,
    metric_col: str = "metrics.cvssMetricV31",
    bins: Sequence[float] = DEFAULT_SCORE_BINS,
    title: str | None = None,
) -> Figure:
    """
    CVSS baseScore를 지정된 구간(bin)으로 나누어 분포를 막대 그래프로 그리는 함수.

    동작 개요:
    1. extract_cvss_metrics()를 호출하여 baseScore를 포함한 DataFrame을 얻는다.
    2. bins(예: [0,3,6,8,10])에 따라 baseScore를 구간으로 나눈다(pd.cut 사용).
    3. 각 구간별 개수를 집계하여 bar chart로 시각화한다.

    매개변수 설명:
    - metric_col: 사용할 CVSS 메트릭 컬럼 이름 (v3.1, v2 등)
    - bins: 점수 구간 경계 리스트(또는 튜플). DEFAULT_SCORE_BINS 사용 시 0–3, 3–6, 6–8, 8–10으로 나눔.
    - title: 그래프 제목(없으면 기본 제목 사용)

    활용 시나리오:
    - 데이터셋 전체의 baseScore 분포를 "저위험~고위험" 구간으로 나누어 보고 싶을 때
    - CVSS v3.1과 v2의 점수 분포 특성을 비교할 때
    """
    # 1) CVSS 메트릭에서 baseScore/baseSeverity 추출
    metrics_df = extract_cvss_metrics(df, metric_col=metric_col)

    # 2) bins 경계값으로부터 구간 라벨 문자열 생성 (예: "0-3", "3-6"...)
    labels = _bin_labels(bins)

    # 3) baseScore를 구간으로 나누어 score_bin이라는 새 범주형 컬럼 생성
    metrics_df["score_bin"] = pd.cut(
        metrics_df["baseScore"],  # 실제 점수 값
        bins=bins,                # 구간 경계값 리스트
        right=False,              # 구간을 [start, end) 형태로 처리 (우측 미포함)
        include_lowest=True,      # 최소값 포함
        labels=labels,            # 각 구간에 대한 레이블 지정
    )

    # 4) 구간별 개수 집계
    summary = (
        metrics_df["score_bin"]
        .value_counts(sort=False)      # 구간 순서를 유지한 채로 빈도 계산
        .rename_axis("score_bin")      # index 이름 지정
        .reset_index(name="count")     # index를 컬럼으로 변환 + count 컬럼 생성
    )

    # 5) 막대 그래프 생성
    fig = px.bar(
        summary,
        x="score_bin",  # x축: 점수 구간 라벨 ("0-3" 등)
        y="count",      # y축: 개수
        category_orders={"score_bin": labels},  # x축 레이블 순서를 bins 순서대로 고정
        labels={"score_bin": "Base Score Range", "count": "Count"},  # 축 레이블
        title=title or f"CVSS baseScore distribution ({metric_col})",  # 제목
    )

    # 6) 레이아웃 여백 조정
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


def summarize_cvss_availability(df: pd.DataFrame) -> pd.DataFrame:
    """
    Summarize presence and completeness of CVSS metrics columns.

    이 함수의 역할:
    - DataFrame 내에서 CVSS 관련 컬럼들(metrics.cvssMetricV31, metrics.cvssMetricV2)에
      실제로 얼마나 데이터가 들어 있는지 요약 테이블을 만들어 반환한다.

    요약 내용:
    - metric_col: 검사한 메트릭 컬럼 이름 (v3.1 / v2)
    - column_present: 해당 컬럼이 DataFrame에 존재하는지 여부
    - rows_with_metrics: NaN이 아닌(무언가 메트릭이 있는) 행의 개수
    - metric_items: explode() 이후의 개별 메트릭 아이템 수 (리스트를 풀어서 센 수)
    - baseScore_non_null: cvssData.baseScore가 채워져 있는 항목 수
    - baseSeverity_non_null: baseSeverity가 채워져 있는 항목 수

    활용 시나리오:
    - 분석에 앞서, 이 데이터셋이 CVSS v3.1 / v2 정보가 얼마나 잘 채워져 있는지 빠르게 점검할 때
    - 어떤 버전(CVSS v3.1 vs v2)을 주 분석 대상으로 삼을지 결정할 때
    """
    rows: list[dict] = []  # 각 metric_col에 대한 요약 정보를 담을 딕셔너리 리스트

    # 두 종류의 CVSS 메트릭 컬럼에 대해 순차적으로 요약 정보 생성
    for metric_col in ("metrics.cvssMetricV31", "metrics.cvssMetricV2"):
        # 1) 해당 컬럼의 존재 여부
        present = metric_col in df.columns

        # 2) 컬럼이 있을 경우, NaN이 아닌 행만 추출
        non_null_rows = df[metric_col].dropna() if present else pd.Series(dtype=object)

        # 3) 리스트 형태를 explode하여 개별 메트릭 수준으로 펼침
        exploded = non_null_rows.explode().dropna() if present else pd.Series(dtype=object)

        base_score_count = base_severity_count = 0  # 기본값 초기화
        if not exploded.empty:
            # explode 결과를 다시 json_normalize로 평탄화
            normalized = pd.json_normalize(exploded)

            # baseScore가 채워져 있는 항목 수
            base_score_count = normalized.get("cvssData.baseScore", pd.Series(dtype=float)).notna().sum()

            # baseSeverity가 채워져 있는 항목 수
            base_severity_count = normalized.get("baseSeverity", pd.Series(dtype=object)).notna().sum()

        # 4) 한 줄 요약 딕셔너리를 rows에 추가
        rows.append(
            {
                "metric_col": metric_col,                        # 메트릭 컬럼 이름
                "column_present": present,                       # 컬럼 존재 여부
                "rows_with_metrics": int(len(non_null_rows)),    # NaN이 아닌 행 개수
                "metric_items": int(len(exploded)),              # explode된 총 메트릭 개수
                "baseScore_non_null": int(base_score_count),     # baseScore가 있는 항목 수
                "baseSeverity_non_null": int(base_severity_count),  # baseSeverity가 있는 항목 수
            }
        )

    # rows 리스트를 DataFrame으로 변환해서 반환
    return pd.DataFrame(rows)


def _bin_labels(bins: Sequence[float]) -> list[str]:
    """
    구간 경계 리스트로부터 'start-end' 형태의 문자열 라벨 리스트를 생성하는 유틸 함수.

    예:
    - bins = [0, 3, 6] → 결과: ["0-3", "3-6"]

    역할:
    - build_cvss_score_bin_chart에서 x축 레이블로 사용할 문자열 생성
    """
    labels: list[str] = []
    # bins를 인접한 두 개씩 쌍으로 묶어서(start, end) 형태로 순회
    for start, end in zip(bins[:-1], bins[1:]):
        # 소수점 없는 형태로 구간 문자열 생성 후 리스트에 추가
        labels.append(f"{start:.0f}-{end:.0f}")
    return labels


# 이 모듈에서 외부에 공개(export)할 함수 목록 정의
# from <module> import * 사용 시 아래에 나열된 심볼만 import됨
__all__ = [
    "extract_cvss_metrics",        # CVSS 메트릭(리스트)를 평평한 DataFrame으로 변환하는 함수
    "build_cvss_severity_chart",   # severity 분포 막대 그래프 생성 함수
    "build_cvss_score_bin_chart",  # baseScore 구간 분포 막대 그래프 생성 함수
    "summarize_cvss_availability", # CVSS 데이터 존재 여부/완전성 요약 함수
]
