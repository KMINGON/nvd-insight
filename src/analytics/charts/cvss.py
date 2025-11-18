from __future__ import annotations  # 향후 버전의 타입 힌트 기능 사용 (예: | 문법 등)

from typing import Iterable, Sequence  # 타입 힌트용 타입들 불러오기

import pandas as pd  # 데이터 처리 라이브러리
import plotly.express as px  # Plotly 간단 인터페이스
from plotly.graph_objects import Figure  # 반환 타입으로 사용할 Figure 클래스

# CVSS severity 순서를 고정하기 위한 리스트 (LOW → CRITICAL 순)
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# 요일 순서를 고정하기 위한 리스트 (월요일 → 일요일)
DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# CVSS 점수 기본 구간 (0–3, 3–6, 6–8, 8–10)
DEFAULT_SCORE_BINS: tuple[float, ...] = (0, 3, 6, 8, 10)

# 시간(hour) 기본 구간 (0–6, 6–12, 12–18, 18–24)
DEFAULT_HOUR_BINS: tuple[int, ...] = (0, 6, 12, 18, 24)


# ---------------------------------------------------------------------------
# 시간(Time) 기반 차트
#   - 날짜 컬럼을 기준으로 월별, 요일별, 시간대별 분포를 그리는 함수들
# ---------------------------------------------------------------------------
def _ensure_datetime(df: pd.DataFrame, date_col: str) -> pd.Series:
    """
    date_col 컬럼을 datetime으로 변환한 시리즈를 반환.
    컬럼이 없으면 에러를 발생시킨다.
    """
    if date_col not in df.columns:  # df에 date_col이 없으면
        raise ValueError(f"{date_col} column missing from dataframe")  # 에러 발생
    return pd.to_datetime(df[date_col], errors="coerce")  # 문자열/객체를 datetime으로 변환, 실패 시 NaT


def build_monthly_count_chart(
    df: pd.DataFrame,
    *,
    date_col: str = "published",  # 날짜로 사용할 컬럼명 기본값
    title: str | None = None,     # 그래프 제목 (없으면 기본 제목 사용)
) -> Figure:
    """
    월(Year-Month) 단위로 CVE 개수를 집계하는 막대 그래프를 생성한다.
    """
    ts = _ensure_datetime(df, date_col)  # 날짜 컬럼을 datetime 시리즈로 변환
    summary = (
        ts.dt.to_period("M")        # 월 단위 Period로 변환 (예: 2023-01)
        .dropna()                   # NaT(결측) 제거
        .value_counts()             # 각 월별 개수 카운트
        .sort_index()               # 월(Period) 기준으로 정렬
        .rename_axis("year_month")  # index 이름을 year_month로 지정
        .reset_index(name="count")  # index를 컬럼으로 빼고 count 컬럼 생성
    )
    summary["year_month"] = summary["year_month"].astype(str)  # Period를 문자열로 변환 (그래프 x축 표시용)
    if summary.empty:  # 데이터가 하나도 없으면
        raise ValueError("No records available to plot monthly chart")  # 에러 발생
    fig = px.bar(
        summary,  # 막대 그래프에 사용할 데이터프레임
        x="year_month",  # x축: 연-월
        y="count",       # y축: 개수
        labels={"year_month": "Year-Month", "count": "Count"},  # 축 레이블
        title=title or "CVE count by month",  # 제목 (없으면 기본 문자열)
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))  # 그래프 주변 여백 설정
    return fig  # Plotly Figure 반환


def build_dayofweek_chart(
    df: pd.DataFrame,
    *,
    date_col: str = "published",  # 날짜 컬럼명
    title: str | None = None,     # 그래프 제목
) -> Figure:
    """
    요일별 CVE 개수를 집계하는 막대 그래프를 생성한다.
    """
    ts = _ensure_datetime(df, date_col)  # 날짜 컬럼을 datetime 시리즈로 변환
    summary = (
        ts.dt.day_name()      # 요일 이름으로 변환 (예: Monday, Tuesday)
        .dropna()             # NaT 제거
        .value_counts()       # 요일별 개수 카운트
        .reindex(DAY_ORDER)   # Monday~Sunday 순서대로 재정렬 (없는 요일은 NaN)
        .fillna(0)            # NaN을 0으로 채움
        .rename_axis("day_name")     # index 이름 지정
        .reset_index(name="count")   # index를 컬럼으로 빼고 count 컬럼 생성
    )
    fig = px.bar(
        summary,
        x="day_name",  # x축: 요일 이름
        y="count",     # y축: 개수
        category_orders={"day_name": DAY_ORDER},  # 요일 정렬 순서를 강제로 지정
        labels={"day_name": "Day of Week", "count": "Count"},  # 축 레이블
        title=title or "CVE count by day of week",  # 제목
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))  # 여백 설정
    return fig


def build_hourly_chart(
    df: pd.DataFrame,
    *,
    date_col: str = "published",                  # 날짜 컬럼명
    hour_bins: Sequence[int] | None = DEFAULT_HOUR_BINS,  # 시간 구간 (None이면 생시간 사용)
    title: str | None = None,                     # 그래프 제목
) -> Figure:
    """
    하루 24시간 중 어느 시간대에 CVE가 많이 나오는지 시각화하는 함수.
    """
    ts = _ensure_datetime(df, date_col)  # 날짜 컬럼을 datetime으로 변환
    hours = ts.dt.hour.dropna()          # 시간(hour)만 추출하고 NaN 제거
    if hours.empty:  # 유효한 시간이 없으면
        raise ValueError("No valid hours in datetime column to plot")  # 에러

    if hour_bins:  # 시간 구간(bins)이 설정된 경우 (구간별 버킷)
        labels = _bin_labels(hour_bins)  # 구간 라벨 생성 (예: 0-6, 6-12...)
        hours_binned = pd.cut(
            hours,                 # 실제 시간 값들
            bins=hour_bins,        # 구간 경계 리스트
            right=False,           # 오른쪽 경계 포함 여부 (여기선 [start, end) 형태)
            include_lowest=True,   # 최솟값 포함
            labels=labels,         # 각 구간에 대한 레이블 지정
        )
        summary = (
            hours_binned
            .value_counts(sort=False)           # 구간 순서를 유지하면서 빈도 카운트
            .rename_axis("hour_bin")           # index 이름 지정
            .reset_index(name="count")         # index를 컬럼으로 빼고 count 컬럼 생성
        )
        x_col = "hour_bin"                     # x축 컬럼 이름
        category_orders = {"hour_bin": labels} # 구간 순서 고정
    else:  # 구간 없이 실제 0~23시 단위로 그래프를 그리고 싶을 때
        summary = (
            hours.value_counts()   # 시간별 개수 카운트
            .sort_index()          # 0,1,2,...순으로 정렬
            .rename_axis("hour")   # index 이름
            .reset_index(name="count")  # index를 hour 컬럼으로 변환
        )
        x_col = "hour"             # x축: 실제 시간
        category_orders = None     # 정렬 순서를 따로 강제하지 않음

    fig = px.bar(
        summary,
        x=x_col,               # x축: hour 또는 hour_bin
        y="count",             # y축: 개수
        category_orders=category_orders,  # 필요 시 카테고리 순서 지정
        labels={x_col: "Hour" if not hour_bins else "Hour Bucket", "count": "Count"},
        title=title or "CVE count by hour of day",  # 제목
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))  # 여백
    return fig


# ---------------------------------------------------------------------------
# CVSS 기반 차트
#   - CVSS 메트릭 리스트에서 baseScore / baseSeverity를 추출하고
#     severity 분포와 점수 구간 분포를 시각화
# ---------------------------------------------------------------------------
def extract_cvss_metrics(df: pd.DataFrame, metric_col: str = "metrics.cvssMetricV31") -> pd.DataFrame:
    """
    CVSS 메트릭 리스트 컬럼(metric_col)을 explode 한 뒤
    baseSeverity / baseScore만 남긴 DataFrame을 반환한다.
    """
    if metric_col not in df.columns:  # 해당 컬럼이 없는 경우
        raise ValueError(f"{metric_col} column missing; confirm dataset normalization")  # 에러
    exploded = df[metric_col].explode().dropna()  # 리스트 컬럼을 행 단위로 펼치고 NaN 제거
    if exploded.empty:  # 펼친 결과가 아무것도 없으면
        raise ValueError(f"No CVSS metrics found in {metric_col}")  # 에러

    normalized = pd.json_normalize(exploded)  # JSON 구조를 평탄화 (딕셔너리 → 컬럼들)
    if "cvssData.baseScore" not in normalized.columns:  # baseScore 컬럼이 없으면
        raise ValueError("cvssData.baseScore missing in CVSS metrics payload")  # 에러

    # baseSeverity가 상위 또는 cvssData 하위 어디에 있어도 잡아오도록 처리
    if "baseSeverity" in normalized.columns:
        severity_col = normalized["baseSeverity"]
    else:
        severity_col = normalized.get("cvssData.baseSeverity")
    subset = pd.DataFrame(
        {
            "baseScore": normalized["cvssData.baseScore"],   # 점수
            "baseSeverity": severity_col,                    # 심각도
        }
    )
    # baseSeverity를 문자열 대문자로 통일 (LOW, MEDIUM, HIGH, CRITICAL 형태)
    subset["baseSeverity"] = subset["baseSeverity"].astype(str).str.upper()

    # baseScore가 있는 행만 반환 (score가 없는 메트릭은 분석에서 제외)
    return subset.dropna(subset=["baseScore"])


def build_cvss_severity_chart(
    df: pd.DataFrame,
    *,
    metric_col: str = "metrics.cvssMetricV31",  # 사용할 CVSS 메트릭 컬럼
    title: str | None = None,                  # 그래프 제목
) -> Figure:
    """
    baseSeverity 기준으로 CVE 개수를 세고 막대 그래프로 시각화한다.
    """
    metrics_df = extract_cvss_metrics(df, metric_col=metric_col)  # baseScore/baseSeverity 추출
    counts = metrics_df["baseSeverity"].value_counts()            # severity별 개수 카운트
    counts = counts.reindex(SEVERITY_ORDER, fill_value=0)         # 지정한 순서로 재배치, 없는 값은 0
    summary = counts.rename_axis("baseSeverity").reset_index(name="count")  # DataFrame 형태로 변환

    fig = px.bar(
        summary,
        x="baseSeverity",  # x축: severity
        y="count",         # y축: 개수
        category_orders={"baseSeverity": SEVERITY_ORDER},  # severity 순서 고정
        labels={"baseSeverity": "Base Severity", "count": "Count"},  # 축 레이블
        title=title or f"CVSS severity distribution ({metric_col})",  # 제목 (컬럼명 포함)
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))  # 여백
    return fig


def build_cvss_score_bin_chart(
    df: pd.DataFrame,
    *,
    metric_col: str = "metrics.cvssMetricV31",            # CVSS 메트릭 컬럼명
    bins: Sequence[float] = DEFAULT_SCORE_BINS,          # 점수 구간 (기본: 0,3,6,8,10)
    title: str | None = None,                            # 제목
) -> Figure:
    """
    CVSS baseScore를 구간별로 나누고(0–3, 3–6, 6–8, 8–10) 분포를 시각화한다.
    """
    metrics_df = extract_cvss_metrics(df, metric_col=metric_col)  # baseScore/baseSeverity 추출
    labels = _bin_labels(bins)                                   # 구간 레이블 생성

    # baseScore를 지정한 bins로 나누어 score_bin 컬럼 생성
    metrics_df["score_bin"] = pd.cut(
        metrics_df["baseScore"],  # 실제 점수
        bins=bins,                # 경계 값 리스트
        right=False,              # [start, end) 형태로 구간 설정
        include_lowest=True,      # 최소값 포함
        labels=labels,            # 각 구간 레이블
    )

    summary = (
        metrics_df["score_bin"]
        .value_counts(sort=False)             # 구간 순서를 유지한 채 빈도 카운트
        .rename_axis("score_bin")             # index 이름 지정
        .reset_index(name="count")            # index를 컬럼으로 변환, count 컬럼 추가
    )

    fig = px.bar(
        summary,
        x="score_bin",                 # x축: 점수 구간
        y="count",                     # y축: 개수
        category_orders={"score_bin": labels},  # 구간 순서 고정
        labels={"score_bin": "Base Score Range", "count": "Count"},  # 축 레이블
        title=title or f"CVSS baseScore distribution ({metric_col})",  # 제목
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))  # 여백
    return fig


# ---------------------------------------------------------------------------
# CWE 기반 차트
#   - cwes 컬럼(리스트/딕셔너리)을 펼쳐서 CWE ID별 빈도 Top-N을 시각화
# ---------------------------------------------------------------------------
def build_cwe_top_chart(
    df: pd.DataFrame,
    *,
    top_n: int = 20,             # 상위 몇 개까지 보여줄지
    title: str | None = None,    # 제목
) -> Figure:
    """
    CWE 리스트를 explode해서 가장 많이 등장한 CWE ID 상위 N개를 막대 그래프로 시각화한다.
    """
    if "cwes" not in df.columns:  # cwes 컬럼이 없으면
        raise ValueError("cwes column missing from dataframe")  # 에러

    exploded = df["cwes"].explode().dropna()  # 리스트 컬럼을 펼치고 NaN 제거
    if exploded.empty:  # 하나도 없으면
        raise ValueError("No CWE entries available to plot")  # 에러

    # 값이 dict이면 cweId 필드를 꺼내고, 아니면 문자열로 바로 사용
    cwe_ids = exploded.apply(lambda x: x.get("cweId") if isinstance(x, dict) else x)

    # CWE ID별 개수 카운트 후 상위 N개 추출
    counts = (
        cwe_ids.value_counts()
        .head(top_n)                  # 상위 N개
        .rename_axis("cweId")         # index 이름을 cweId로 지정
        .reset_index(name="count")    # index를 컬럼으로 변환, count 컬럼 생성
    )

    fig = px.bar(
        counts,
        x="cweId",  # x축: CWE ID
        y="count",  # y축: 개수
        labels={"cweId": "CWE ID", "count": "Count"},  # 축 레이블
        title=title or f"Top {top_n} CWE categories",  # 제목
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40), xaxis_tickangle=-45)  # x축 라벨 기울여서 가독성 개선
    return fig


# ---------------------------------------------------------------------------
# 유틸리티
#   - 구간 레이블 생성
#   - CVSS 데이터 존재 여부 요약
# ---------------------------------------------------------------------------
def _bin_labels(bins: Sequence[float]) -> list[str]:
    """
    구간 경계 리스트를 받아서 'start-end' 형태의 문자열 리스트를 만들어준다.
    예: [0, 3, 6] → ["0-3", "3-6"]
    """
    labels = []  # 결과 레이블 리스트
    for start, end in zip(bins[:-1], bins[1:]):  # 연속된 두 값을 묶어서(start, end) 쌍 생성
        labels.append(f"{start:.0f}-{end:.0f}")  # 소수점 없이 start-end 형식 문자열로 변환
    return labels


def summarize_cvss_availability(df: pd.DataFrame) -> pd.DataFrame:
    """
    DataFrame 내에 CVSS 데이터가 얼마나 들어 있는지 요약하는 테이블을 반환한다.

    - metrics.cvssMetricV31 / metrics.cvssMetricV2 컬럼이 존재하는지
    - 각 컬럼에서:
        - Non-null 행 개수
        - explode 후 총 메트릭 아이템 개수
        - baseScore / baseSeverity 가 null이 아닌 개수
    """
    rows: list[dict] = []  # 요약 정보를 담을 딕셔너리들의 리스트

    # 두 종류의 CVSS 메트릭 컬럼을 차례대로 검사
    for metric_col in ("metrics.cvssMetricV31", "metrics.cvssMetricV2"):
        present = metric_col in df.columns  # 해당 컬럼 존재 여부
        non_null_rows = df[metric_col].dropna() if present else pd.Series(dtype=object)  # NaN 제거
        exploded = non_null_rows.explode().dropna() if present else pd.Series(dtype=object)  # 리스트를 펼쳐서 개별 메트릭 단위로

        base_score_count = base_severity_count = 0  # 기본값 0
        if not exploded.empty:
            normalized = pd.json_normalize(exploded)  # JSON 평탄화
            # baseScore가 null이 아닌 개수
            base_score_count = normalized.get("cvssData.baseScore", pd.Series(dtype=float)).notna().sum()
            # baseSeverity가 null이 아닌 개수
            base_severity_count = normalized.get("baseSeverity", pd.Series(dtype=object)).notna().sum()

        # 한 줄 요약 정보 딕셔너리 생성
        rows.append(
            {
                "metric_col": metric_col,                    # 메트릭 컬럼 이름
                "column_present": present,                   # 컬럼 존재 여부
                "rows_with_metrics": int(len(non_null_rows)),# NaN이 아닌 행 개수
                "metric_items": int(len(exploded)),          # explode 후 총 메트릭 아이템 개수
                "baseScore_non_null": int(base_score_count), # baseScore 있는 개수
                "baseSeverity_non_null": int(base_severity_count),  # baseSeverity 있는 개수
            }
        )

    return pd.DataFrame(rows)  # 요약 결과를 DataFrame으로 반환


# 이 모듈을 from xxx import * 로 불러올 때 공개할 함수 목록
__all__ = [
    "build_monthly_count_chart",     # 월별 카운트 차트
    "build_dayofweek_chart",         # 요일별 카운트 차트
    "build_hourly_chart",            # 시간대별 카운트 차트
    "build_cvss_severity_chart",     # CVSS severity 분포 차트
    "build_cvss_score_bin_chart",    # CVSS 점수 구간 분포 차트
    "build_cwe_top_chart",           # CWE Top-N 차트
    "summarize_cvss_availability",   # CVSS 데이터 존재 여부 요약 테이블
    "extract_cvss_metrics",          # CVSS 메트릭 추출 함수
]
