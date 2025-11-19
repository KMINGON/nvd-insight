from __future__ import annotations  # 향후 타입 힌트 문법(예: |)을 사용하기 위해 추가

import pandas as pd  # 데이터 처리/집계를 위한 pandas
import plotly.express as px  # Plotly의 간단한 시각화 인터페이스
from plotly.graph_objects import Figure  # 반환 타입으로 사용할 Plotly Figure 클래스


def summarize_cwe_counts(df: pd.DataFrame, top_n: int = 20) -> pd.DataFrame:
    """
    DataFrame에서 CWE ID별 등장 횟수를 집계하고,
    상위 top_n개만 정리한 요약 테이블(DataFrame)을 반환하는 함수.

    역할:
    - df["cwes"] 컬럼(리스트 또는 dict/문자열)을 explode해서
      각 CWE ID의 빈도를 계산한다.
    - 가장 많이 등장한 CWE top_n개를 'cweId' / 'count' 형태로 반환한다.

    활용 예:
    - 어떤 CWE 유형이 가장 자주 등장하는지 Top 20 목록을 보고 싶을 때
    - 시각화(build_cwe_top_chart)의 입력 데이터로 사용
    """
    # 1) cwes 컬럼이 DataFrame에 없으면 분석 자체가 불가능하므로 예외 발생
    if "cwes" not in df.columns:
        raise ValueError("cwes column missing from dataframe")

    # 2) cwes 컬럼은 보통 리스트 형태이므로 explode()로 행 단위로 펼치고 NaN 제거
    exploded = df["cwes"].explode().dropna()
    if exploded.empty:
        # cwes 항목이 전혀 없으면 요약해줄 데이터가 없으므로 예외 발생
        raise ValueError("No CWE entries available to summarize")

    # 3) 값이 dict인 경우에는 x["cweId"]를 꺼내고,
    #    이미 문자열(CWE-79 같은 ID)이면 그대로 사용
    cwe_ids = exploded.apply(lambda x: x.get("cweId") if isinstance(x, dict) else x)

    # 4) CWE ID별 등장 횟수(value_counts)를 구하고,
    #    상위 top_n개까지만 남긴 뒤, cweId / count 형태의 DataFrame으로 정리
    summary = (
        cwe_ids.value_counts()    # CWE ID별 빈도 계산
        .head(top_n)              # 상위 top_n개만 선택
        .rename_axis("cweId")     # index 이름을 cweId로 지정
        .reset_index(name="count")  # index를 컬럼으로 빼고 count 컬럼 이름 지정
    )
    return summary  # cweId / count 두 컬럼을 가진 요약 DataFrame 반환


def build_cwe_top_chart(
    df: pd.DataFrame,
    *,
    top_n: int = 20,
    title: str | None = None,
) -> Figure:
    """
    CWE ID별 등장 횟수 상위 top_n개를 막대 그래프로 시각화하는 함수.

    동작 개요:
    1. summarize_cwe_counts()를 호출해 'cweId' / 'count' 요약 테이블을 얻는다.
    2. Plotly의 bar 차트를 사용해 CWE ID별 빈도 막대 그래프를 그린다.
    3. x축 레이블이 겹치지 않도록 x축 텍스트를 기울여 표시한다.

    매개변수:
    - df: NVD JSON을 normalize한 전체 DataFrame
    - top_n: 상위 몇 개의 CWE ID를 표시할지 (기본 20개)
    - title: 그래프 제목 (None이면 기본 제목 "Top {top_n} CWE categories" 사용)

    활용 예:
    - 가장 자주 등장하는 취약점 유형(CWE)을 한눈에 보고 싶을 때
    - 보안 리포트나 대시보드에서 CWE 통계 섹션에 사용
    """
    # 1) 상위 top_n개의 CWE 요약 테이블 생성
    summary = summarize_cwe_counts(df, top_n=top_n)

    # 2) bar 차트 생성: x축에 CWE ID, y축에 개수
    fig = px.bar(
        summary,
        x="cweId",   # x축: CWE ID
        y="count",   # y축: 등장 횟수
        labels={"cweId": "CWE ID", "count": "Count"},  # 축 레이블 지정
        title=title or f"Top {top_n} CWE categories",  # 제목: 인자로 안 주면 기본 제목 사용
    )

    # 3) 레이아웃 조정:
    #    - 그래프 주변 여백(margin) 설정
    #    - x축 라벨을 -45도 기울여서 많은 CWE ID가 있어도 겹치지 않게 함
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40), xaxis_tickangle=-45)
    return fig  # Plotly Figure 반환


# 이 모듈에서 외부에 공개(export)할 함수 목록 정의
# from <module> import * 사용할 때 아래 심볼들만 외부로 노출된다.
__all__ = [
    "summarize_cwe_counts",  # CWE 빈도 상위 N개 요약 DataFrame 생성 함수
    "build_cwe_top_chart",   # CWE Top-N 막대 그래프 생성 함수
]
