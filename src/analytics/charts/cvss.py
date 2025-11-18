from __future__ import annotations  # 향후 버전의 타입 힌트 기능 사용 (예: | 문법 등)

from typing import Iterable, Sequence  # 타입 힌트용 타입들 불러오기

import pandas as pd  # 데이터 처리 라이브러리
import plotly.express as px  # Plotly 간단 인터페이스
from plotly.graph_objects import Figure  # 반환 타입으로 사용할 Figure 클래스

# 요일 순서를 고정하기 위한 리스트 (월요일 → 일요일)
DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

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


__all__ = [
    "build_monthly_count_chart",     # 월별 카운트 차트
    "build_dayofweek_chart",         # 요일별 카운트 차트
    "build_hourly_chart",            # 시간대별 카운트 차트
]
