from __future__ import annotations

from typing import Optional, Tuple

import pandas as pd
import streamlit as st

from src.analytics.charts import skr_score
from src.rag import RagRetriever
from ..chat import streamlit_chat
from ..common import build_session_key


def render_skr_score_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """SKR Score 인사이트 페이지의 슬라이더, 차트, AI 요약 탭을 렌더링한다."""

    enriched = skr_score.build_skr_score_added_df(df)
    top10_df = skr_score.build_top10_dataset(source_df=enriched)

    analysis_tab, severity_tab, band_tab, compare_tab, exploit_tab, ai_tab = st.tabs([
        "분석 시각화",
        "심각도 vs 악용",
        "위험도 구간",
        "CVSS vs SKR",
        "악용 속도 분석",
        "AI 요약 리포트",
    ])
    with analysis_tab:
        st.markdown("**SKR Score 인사이트 파라미터**")
        score_threshold = st.slider(
            "SKR Score 최소값",
            min_value=5.0,
            max_value=9.5,
            value=7.0,
            step=0.5,
            key="skr_threshold_slider",
        )
        top_n = st.slider("Top-N 범위 (벤더/제품/CWE)", min_value=5, max_value=20, value=10, key="skr_topn_slider")
        vendor_summary = skr_score.summarize_vendor_counts(enriched, top_n=top_n, threshold=score_threshold)
        product_summary = skr_score.summarize_product_counts(enriched, top_n=top_n, threshold=score_threshold)
        cwe_summary = skr_score.summarize_cwe_scores(enriched, top_n=top_n, threshold=score_threshold)

        st.plotly_chart(skr_score.build_top10_timeline_chart(top10_df), use_container_width=True)
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(
                skr_score.build_vendor_score_chart(vendor_summary, "SKR 고위험 벤더"),
                use_container_width=True,
            )
            st.dataframe(vendor_summary)
        with col2:
            st.plotly_chart(
                skr_score.build_product_score_chart(product_summary, "SKR 고위험 제품"),
                use_container_width=True,
            )
            st.dataframe(product_summary)

        st.plotly_chart(
            skr_score.build_cwe_score_chart(cwe_summary, "SKR 고위험 CWE"),
            use_container_width=True,
        )
        st.dataframe(cwe_summary)

    with severity_tab:
        st.markdown("**CVSS 심각도별 악용 분포**")
        severity_summary = skr_score.summarize_severity_cisa(enriched)
        st.plotly_chart(skr_score.build_severity_cisa_chart(severity_summary), use_container_width=True)
        st.caption(
            "각 Severity 내에서 CISA 악용 건수와 평균 SKR Score를 비교해, '심각도가 낮아도 악용되면 위험하다'는 메시지를 전달합니다. "
            "Critical이 아니어도 실제로 악용된 취약점이 존재하는지 확인할 수 있고, Medium인데도 빨간 막대가 보인다면 단순 점수만 보고 무시하면 안 됩니다."
        )
        st.dataframe(severity_summary)

    with band_tab:
        st.markdown("**SKR Score 위험도 구간(Band) 분포 시각화**")
        _, band_summary = skr_score.summarize_skr_band_distribution(enriched)
        st.plotly_chart(skr_score.build_skr_band_pie_chart(band_summary), use_container_width=True)
        st.caption("1년치 취약점 중 실제 위험도가 높은 구간이 어느 정도 비중을 차지하는지 보여줍니다.")
        st.plotly_chart(skr_score.build_skr_band_exploit_ratio_chart(band_summary), use_container_width=True)
        st.caption("각 위험도 구간 안에서 실제 악용된 비중을 별도로 확인해 구체적인 우선순위를 잡을 수 있습니다.")
        st.plotly_chart(skr_score.build_skr_band_dual_axis_chart(band_summary), use_container_width=True)
        st.caption("막대는 전체 CVE 건수, 선은 악용 비율(%)을 나타내어 '규모+비중'을 동시에 확인합니다.")
        if not band_summary.empty:
            band_table = band_summary.copy()
            band_table["ratio"] = (band_table["ratio"] * 100).map(lambda v: f"{v:.1f}%")
            st.dataframe(band_table.rename(columns={"band": "구간", "count": "건수", "ratio": "비율", "exploited": "악용 건수"}))
        else:
            st.info("SKR Score 구간 분포를 계산할 데이터가 없습니다.")

    # CVSS 기본 점수와 SKR 점수를 비교해 재조정 효과를 해석하는 탭
    with compare_tab:
        st.markdown("**CVSS vs SKR 점수 비교**")
        # 산점도: 개별 취약점에서 CVSS 대비 SKR 조정 방향 확인
        st.plotly_chart(skr_score.build_cvss_skr_scatter(enriched), use_container_width=True)
        st.caption(
            "대각선 위에 위치한 점은 SKR Score가 CVSS보다 높게 평가된 것으로, 악용 보고(빨간색)일수록 해당 영역에 모여야 정상적인 위험 조정이 이루어진 것입니다."
        )

        severity_means = skr_score.summarize_severity_score_means(enriched)
        # 막대: 각 Severity 그룹에서 평균 CVSS와 평균 SKR 변화를 비교
        st.plotly_chart(skr_score.build_severity_score_compare_chart(severity_means), use_container_width=True)
        if not severity_means.empty:
            st.dataframe(
                severity_means.rename(
                    columns={
                        "baseSeverity": "Severity",
                        "avgBaseScore": "평균 CVSS",
                        "avgSkrScore": "평균 SKR",
                    }
                )
            )
        else:
            st.info("Severity별 평균을 계산할 데이터가 없습니다.")
        st.caption(
            "같은 Severity라 해도 exploitability·CISA 플래그를 반영하면 SKR 평균이 더 높아질 수 있으며, Medium에서도 실제 악용 케이스가 섞이면 점수가 상승합니다."
        )

        # 히스토그램: 편차 분포와 CISA 플래그를 동시에 체크
        st.plotly_chart(skr_score.build_skr_delta_histogram(enriched), use_container_width=True)
        st.caption(
            "가로축은 SKR Score - CVSS Base Score 편차(음수: SKR이 더 낮음, 0: 비슷, 양수: SKR이 더 높음), "
            "세로축은 해당 구간의 취약점 수, 색상은 CISA 플래그를 나타냅니다."
        )
        st.caption(
            "히스토그램 오른쪽 꼬리는 'CVSS보다 SKR가 더 높은' 취약점이며, 악용 플래그가 있는 점들이 오른쪽에 몰려 있다면 설계 의도가 잘 반영된 것입니다."
        )
        # 막대: 편차 구간별 악용 비율을 확인해 CVSS 대비 조정 효과 진단
        st.plotly_chart(skr_score.build_skr_delta_ratio_chart(enriched), use_container_width=True)
        st.caption("편차 구간별로 실제 악용 비율을 확인해 CVSS 대비 SKR 조정이 어떤 구간에서 가장 효과적인지 파악할 수 있습니다.")

    with exploit_tab:
        st.markdown("**악용까지 걸린 시간 분석**")
        days_df = skr_score.summarize_days_to_exploit(enriched)
        if days_df.empty:
            st.info("악용까지 걸린 시간을 계산할 수 있는 데이터가 없습니다.")
        else:
            col_hist, col_box = st.columns(2)
            with col_hist:
                st.plotly_chart(skr_score.build_days_to_exploit_histogram(days_df), use_container_width=True)
                st.plotly_chart(skr_score.build_days_to_exploit_kde(days_df), use_container_width=True)
            with col_box:
                st.plotly_chart(skr_score.build_days_to_exploit_box(days_df), use_container_width=True)
            st.caption("악용까지 걸린 시간이 짧을수록 긴급 대응이 필요하다는 메시지를 강조합니다.")
            top_n = st.slider("발표 직후 빠르게 악용된 취약점 Top-N", min_value=3, max_value=20, value=5, step=1, key="skr_days_topn")
            top_exploited = days_df.nsmallest(top_n, "days_to_exploit").copy()
            top_exploited["days_to_exploit"] = top_exploited["days_to_exploit"].astype(int)
            st.subheader("발표 직후 빠르게 악용된 취약점 Top-N")
            st.dataframe(
                top_exploited[["cveId", "baseSeverity", "published", "days_to_exploit"]]
                .rename(columns={
                    "cveId": "CVE ID",
                    "baseSeverity": "Severity",
                    "published": "발표일",
                    "days_to_exploit": "악용까지 일수",
                })
            )
            st.caption("짧은 일수 순으로 정렬된 CVE 목록을 기반으로, 즉각적인 패치 우선순위를 판단할 수 있습니다.")

    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return
        system_prompt = (
            "당신은 SKR Score 기반으로 고위험 CVE를 선별하는 한국어 보안 분석가입니다. "
            "반드시 한국어로 답변하며, Top10 CVE와 고위험 벤더/제품/CWE 집계를 바탕으로 위험 요인을 요약하세요."
        )
        session_key = build_session_key("skr_insight", years, suffix=f"thr{score_threshold}")
        streamlit_chat(
            retriever,
            df=top10_df,
            system_prompt=system_prompt,
            session_key=session_key,
        )
