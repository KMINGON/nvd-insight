from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import pandas as pd
import streamlit as st

from ..rag import RagRetriever


@dataclass
class AnalysisSession:
    """분석별 챗봇 세션 스냅샷."""

    session_id: str
    prompt: str
    summary: str
    filters: dict
    history: List[dict] = field(default_factory=list)


class AnalysisChatService:
    """분석 결과 요약 + 후속 질의를 처리하는 Streamlit 헬퍼."""

    def __init__(self, retriever: RagRetriever, session_store: Dict[str, AnalysisSession] | None = None) -> None:
        self.retriever = retriever
        self.sessions = session_store if session_store is not None else {}

    def start_session(self, session_id: str, df: pd.DataFrame, system_prompt: str) -> str:
        """분석 결과 DF를 기반으로 최초 요약 리포트를 생성한다.

        Args:
            session_id (str): Streamlit에서 사용할 세션 키.
            df (pd.DataFrame): 특정 차트/분석에 사용한 데이터프레임.
            system_prompt (str): 모델의 역할과 어조를 정의하는 프롬프트.

        Returns:
            str: 생성된 요약 리포트 텍스트.
        """
        summary = self._summarize_dataframe(df)
        filters = self._build_filters(df)
        report_prompt = self._compose_report_prompt(system_prompt, summary)
        response = self.retriever.generate_response(
            system_prompt=system_prompt,
            user_prompt=report_prompt,
            filters=filters,
            history=[],
        )
        session = AnalysisSession(
            session_id=session_id,
            prompt=system_prompt,
            summary=summary,
            filters=filters,
            history=[{"role": "assistant", "content": response}],
        )
        self.sessions[session_id] = session
        return response

    def send_message(self, session_id: str, message: str) -> str:
        """기존 세션 컨텍스트를 유지한 채 후속 질문을 처리한다.

        Args:
            session_id (str): 조회할 세션 키.
            message (str): 사용자 입력 질문.

        Returns:
            str: 모델이 생성한 답변.
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Unknown session_id: {session_id}")
        user_payload = self._compose_followup_payload(session.summary, message)
        history = list(session.history)
        history.append({"role": "user", "content": message})
        response = self.retriever.generate_response(
            system_prompt=session.prompt,
            user_prompt=user_payload,
            filters=session.filters,
            history=history,
        )
        session.history = history + [{"role": "assistant", "content": response}]
        self.sessions[session_id] = session
        return response

    @staticmethod
    def _summarize_dataframe(df: pd.DataFrame) -> str:
        """차트별로 다양한 DF 포맷을 처리하기 위한 단순 요약.

        Args:
            df (pd.DataFrame): 분석 결과 데이터프레임.

        Returns:
            str: 컬럼, 행 수, 샘플 레코드를 포함한 요약 문자열.
        """
        if df is None or df.empty:
            return "No data provided"
        preview = df.head(5).to_dict(orient="records")
        columns = ", ".join(df.columns.astype(str))
        return (
            f"columns: {columns}\n"
            f"rows: {len(df)}\n"
            f"sample: {preview}"
        )

    @staticmethod
    def _build_filters(df: pd.DataFrame) -> dict:
        """DF에서 RAG 검색에 사용할 메타데이터 필터를 추출한다.

        Args:
            df (pd.DataFrame): 분석 결과 데이터프레임.

        Returns:
            dict: year, cveId 리스트 등 검색 필터.
        """
        filters: dict = {}
        if df is None or df.empty:
            return filters
        if "published" in df.columns:
            year = AnalysisChatService._extract_year(df["published"].iloc[0])
            if year:
                filters["year"] = year
        if "cveId" in df.columns:
            filters["cveId"] = df["cveId"].dropna().tolist()
        vendor_columns = [col for col in ("vendor", "vendors") if col in df.columns]
        if vendor_columns:
            column = vendor_columns[0]
            vendors = sorted({str(value) for value in df[column].dropna() if str(value)})
            if vendors:
                filters["vendors"] = vendors
        product_columns = [col for col in ("product", "products") if col in df.columns]
        if product_columns:
            column = product_columns[0]
            products = sorted({str(value) for value in df[column].dropna() if str(value)})
            if products:
                filters["products"] = products
        cwe_columns = [col for col in ("cweId", "cwe", "cwes") if col in df.columns]
        if cwe_columns:
            column = cwe_columns[0]
            cwes = sorted({str(value) for value in df[column].dropna() if str(value)})
            if cwes:
                filters["cwes"] = cwes
        severity_columns = [col for col in ("baseSeverity", "severity") if col in df.columns]
        if severity_columns:
            column = severity_columns[0]
            severities = sorted(
                {str(value).upper() for value in df[column].dropna() if str(value)}
            )
            if severities:
                filters["severity"] = severities
        return filters

    @staticmethod
    def _compose_report_prompt(system_prompt: str, summary: str) -> str:
        """최초 요약용 사용자 프롬프트를 구성한다."""
        return (
            f"{system_prompt}\n\n"
            "You are summarizing the following analysis dataframe.\n"
            f"Data Summary:\n{summary}\n"
            "Provide an executive report grounded on the retrieved CVE/CWE context."
        )

    @staticmethod
    def _compose_followup_payload(summary: str, message: str) -> str:
        """후속 질문 시 DF 요약과 사용자 입력을 묶는다."""
        return (
            f"Dataset summary: {summary}\n\n"
            f"User question: {message}"
        )

    @staticmethod
    def _extract_year(value: str) -> int | None:
        """문자열(YYYY...)에서 연도 숫자만 추출한다."""
        if not isinstance(value, str) or len(value) < 4:
            return None
        year_part = value[:4]
        return int(year_part) if year_part.isdigit() else None


def streamlit_chat(
    retriever: RagRetriever,
    df: pd.DataFrame | None = None,
    system_prompt: str | None = None,
    session_key: str = "analysis_chat",
) -> None:
    """Streamlit UI에서 분석용 챗봇 세션을 렌더링한다.

    Args:
        retriever (RagRetriever): RAG 검색/응답 핸들러.
        df (pd.DataFrame | None): 해당 분석에서 사용한 데이터프레임.
        system_prompt (str | None): 모델 역할 지시문.
        session_key (str): Streamlit state에 저장할 세션 식별자.
    """

    session_store = st.session_state.setdefault("analysis_sessions", {})
    service = AnalysisChatService(retriever, session_store)
    prompt = system_prompt or "You are a security analyst assistant."

    if df is not None and session_key not in session_store:
        with st.spinner("Generating analysis report..."):
            service.start_session(session_key, df, prompt)

    user_query = st.chat_input("질문을 입력하세요")
    if user_query:
        if session_key not in session_store:
            st.error("세션이 초기화되지 않았습니다. 분석 데이터를 먼저 로드하세요.")
            return
        try:
            answer = service.send_message(session_key, user_query)
        except KeyError as exc:  # pragma: no cover - defensive branch
            st.error(str(exc))
            return
        st.toast("답변이 생성되었습니다.")

    session = session_store.get(session_key)
    if session:
        for message in session.history:
            st.chat_message(message["role"]).write(message["content"])
