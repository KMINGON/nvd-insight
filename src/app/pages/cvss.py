from __future__ import annotations

from typing import Optional, Tuple

import pandas as pd
import streamlit as st

from src.analytics.charts import cvss_app
from src.rag import RagRetriever
from ..chat import streamlit_chat
from ..common import build_session_key


def render_cvss_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """CVSS 지표 분포를 시각화하고 챗봇 요약을 제공한다."""

    metric_options = {
        "CVSS v3.1": "metrics.cvssMetricV31",
        "CVSS v2": "metrics.cvssMetricV2",
    }
    summary_df = cvss_app.summarize_cvss_availability(df)
    severity_summary: Optional[pd.DataFrame] = None
    score_summary: Optional[pd.DataFrame] = None
    selected_metric_label = "CVSS v3.1"
    selected_bins: Tuple[float, ...] = tuple(cvss_app.DEFAULT_SCORE_BINS)
    bins_input_default = ",".join(str(int(value)) for value in cvss_app.DEFAULT_SCORE_BINS)

    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])
    with analysis_tab:
        st.markdown("**CVSS 데이터 존재 여부**")
        st.dataframe(summary_df)

        selected_metric_label = st.radio(
            "CVSS 버전",
            options=list(metric_options.keys()),
            index=0,
            horizontal=True,
            key="cvss_metric_radio",
        )
        metric_col = metric_options[selected_metric_label]

        bins_input = st.text_input(
            "Score bins (콤마 구분)",
            value=bins_input_default,
            help="점수 구간을 직접 지정해 위험도 분포를 세분화할 수 있습니다.",
        )
        try:
            parsed_bins = [float(value.strip()) for value in bins_input.split(",") if value.strip()]
            if len(parsed_bins) < 2:
                raise ValueError("bins must contain at least two numeric edges")
            selected_bins = tuple(parsed_bins)
        except ValueError as exc:
            st.warning(f"점수 구간 입력을 해석할 수 없어 기본값을 사용합니다: {exc}")
            selected_bins = tuple(cvss_app.DEFAULT_SCORE_BINS)

        col1, col2 = st.columns(2)
        with col1:
            try:
                severity_fig = cvss_app.build_cvss_severity_chart(df, metric_col=metric_col)
                st.plotly_chart(severity_fig, use_container_width=True)
                metrics_df = cvss_app.extract_cvss_metrics(df, metric_col=metric_col)
                severity_summary = (
                    metrics_df["baseSeverity"]
                    .value_counts()
                    .reindex(cvss_app.SEVERITY_ORDER, fill_value=0)
                    .rename_axis("label")
                    .reset_index(name="count")
                )
                severity_summary["metric"] = "severity"
            except Exception as exc:
                st.warning(f"Severity 분포를 계산할 수 없습니다: {exc}")
        with col2:
            try:
                score_fig = cvss_app.build_cvss_score_bin_chart(
                    df,
                    metric_col=metric_col,
                    bins=list(selected_bins),
                )
                st.plotly_chart(score_fig, use_container_width=True)
                metrics_df = cvss_app.extract_cvss_metrics(df, metric_col=metric_col)
                labels = [f"{selected_bins[i]:g}-{selected_bins[i + 1]:g}" for i in range(len(selected_bins) - 1)]
                metrics_df["score_bin"] = pd.cut(
                    metrics_df["baseScore"],
                    bins=selected_bins,
                    right=False,
                    include_lowest=True,
                    labels=labels,
                )
                score_summary = (
                    metrics_df["score_bin"]
                    .value_counts(sort=False)
                    .rename_axis("label")
                    .reset_index(name="count")
                )
                score_summary["metric"] = "score_bin"
            except Exception as exc:
                st.warning(f"Score bins 분포를 계산할 수 없습니다: {exc}")

    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return
        context_frames: list[pd.DataFrame] = []
        if not summary_df.empty:
            availability_df = summary_df.copy()
            availability_df["metric"] = "availability"
            context_frames.append(availability_df)
        if severity_summary is not None:
            context_frames.append(severity_summary)
        if score_summary is not None:
            context_frames.append(score_summary)
        if not context_frames:
            st.info("챗봇에 전달할 CVSS 요약 데이터가 없습니다. 데이터 컬럼을 확인하세요.")
            return
        context_df = pd.concat(context_frames, ignore_index=True)
        bins_signature = "-".join(f"{value:g}" for value in selected_bins)
        system_prompt = (
            "당신은 CVSS 점수/심각도 분포를 요약하는 한국어 보안 분석가입니다. "
            "CVSS v3/v2 데이터의 존재 여부, 심각도 비중, 점수 구간별 분포를 기반으로 위험 동향을 설명하세요."
        )
        session_key = build_session_key(
            "cvss_insight",
            years,
            suffix=f"{selected_metric_label.replace(' ', '').lower()}_{bins_signature}",
        )
        streamlit_chat(
            retriever,
            df=context_df,
            system_prompt=system_prompt,
            session_key=session_key,
        )
