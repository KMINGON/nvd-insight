from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import pandas as pd
import streamlit as st

from ..rag import RagRetriever


# 기능: 분석 세션별 상태를 Streamlit state에 저장하기 위한 데이터 클래스.
@dataclass
class AnalysisSession:
    """인사이트별 챗봇 세션 스냅샷."""

    session_id: str
    prompt: str
    summary: str
    filters: dict
    history: List[dict] = field(default_factory=list)


class AnalysisChatService:
    """분석 결과 요약과 후속 질의를 처리하는 Streamlit 헬퍼."""

    # 기능: 분석 챗봇 서비스 인스턴스를 초기화하고 세션 저장소를 설정한다.
    def __init__(self, retriever: RagRetriever, session_store: Dict[str, AnalysisSession] | None = None) -> None:
        self.retriever = retriever
        self.sessions = session_store if session_store is not None else {}

    # 기능: 분석 결과 DF를 기반으로 최초 요약 리포트를 생성하고 세션을 시작한다.
    def start_session(self, session_id: str, df: pd.DataFrame, system_prompt: str) -> str:
        """분석 결과 DF를 기반으로 최초 요약 리포트를 생성한다.

        매개변수:
            session_id: Streamlit에서 사용할 세션 키.
            df: 특정 차트/분석에 사용한 데이터프레임.
            system_prompt: 모델의 역할과 어조를 정의하는 프롬프트.

        반환값:
            생성된 요약 리포트 텍스트.
        """
        # 챗봇이 이해할 수 있도록 DF를 간단히 요약하고 필터 조건을 추출한다.
        summary = self._summarize_dataframe(df)
        filters = self._build_filters(df)
        # 시스템 프롬프트에 데이터 요약을 붙여 실제 모델 입력을 만든다.
        report_prompt = self._compose_report_prompt(system_prompt, summary)
        response = self.retriever.generate_response(
            system_prompt=system_prompt,
            user_prompt=report_prompt,
            filters=filters,
            history=[],
        )
        # 첫 응답을 히스토리에 남겨 후속 질문이 있을 때 그대로 이어 간다.
        session = AnalysisSession(
            session_id=session_id,
            prompt=system_prompt,
            summary=summary,
            filters=filters,
            history=[{"role": "assistant", "content": response}],
        )
        self.sessions[session_id] = session
        return response

    # 기능: 사용자 질문을 기존 세션 컨텍스트에 추가하고 RAG 답변을 반환한다.
    def send_message(self, session_id: str, message: str) -> str:
        """기존 세션 컨텍스트를 유지한 채 후속 질문을 처리한다.

        매개변수:
            session_id: 조회할 세션 키.
            message: 사용자 입력 질문.

        반환값:
            모델이 생성한 답변.
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Unknown session_id: {session_id}")
        # 이전 요약 텍스트와 새 메시지를 합쳐 모델 입력을 구성한다.
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
    # 기능: 데이터프레임의 컬럼/행 수/샘플을 문자열로 요약한다.
    def _summarize_dataframe(df: pd.DataFrame) -> str:
        """차트별로 다양한 DF 포맷을 처리하기 위한 단순 요약.

        매개변수:
            df: 분석 결과 데이터프레임.

        반환값:
            컬럼, 행 수, 샘플 레코드를 포함한 요약 문자열.
        """
        if df is None or df.empty:
            return "No data provided"
        # LangChain에 지나치게 많은 데이터를 넘기지 않도록 상위 5개 행만 직렬화한다.
        preview = df.head(5).to_dict(orient="records")
        columns = ", ".join(df.columns.astype(str))
        return (
            f"columns: {columns}\n"
            f"rows: {len(df)}\n"
            f"sample: {preview}"
        )

    @staticmethod
    # 기능: 데이터프레임에서 RAG 검색 필터(year, vendor 등)를 추출한다.
    def _build_filters(df: pd.DataFrame) -> dict:
        """DF에서 RAG 검색에 사용할 메타데이터 필터를 추출한다.

        매개변수:
            df: 분석 결과 데이터프레임.

        반환값:
            year, cveId 리스트 등 검색 필터.
        """
        filters: dict = {}
        if df is None or df.empty:
            return filters
        # 게시일이 포함된 데이터라면 첫 행의 연도만으로도 검색 범위를 좁힐 수 있다.
        if "published" in df.columns:
            year = AnalysisChatService._extract_year(df["published"].iloc[0])
            if year:
                filters["year"] = year
        # CVE ID는 다수일 수 있으므로 dropna 후 리스트 전체를 전달한다.
        if "cveId" in df.columns:
            filters["cveId"] = df["cveId"].dropna().tolist()
        # 벤더/제품 컬럼은 여러 이름을 허용하므로 우선순위를 정해 하나만 사용한다.
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
        # CWE 표기도 여러 포맷이 존재하므로 가능한 컬럼을 모두 검사한다.
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
    # 기능: 최초 요약 시 시스템 프롬프트와 DF 정보를 결합한 사용자 프롬프트를 생성한다.
    def _compose_report_prompt(system_prompt: str, summary: str) -> str:
        """최초 요약용 사용자 프롬프트를 구성한다."""
        return (
            f"{system_prompt}\n\n"
            "You are summarizing the following analysis dataframe.\n"
            f"Data Summary:\n{summary}\n"
            "Provide an executive report grounded on the retrieved CVE/CWE context."
        )

    @staticmethod
    # 기능: 후속 질문에서 DF 요약과 사용자 입력을 묶은 페이로드를 생성한다.
    def _compose_followup_payload(summary: str, message: str) -> str:
        """후속 질문 시 DF 요약과 사용자 입력을 묶는다."""
        return (
            f"Dataset summary: {summary}\n\n"
            f"User question: {message}"
        )

    @staticmethod
    # 기능: YYYY로 시작하는 문자열에서 연도 숫자만 추출한다.
    def _extract_year(value: str) -> int | None:
        """문자열(YYYY...)에서 연도 숫자만 추출한다."""
        if not isinstance(value, str) or len(value) < 4:
            return None
        year_part = value[:4]
        return int(year_part) if year_part.isdigit() else None


# 기능: Streamlit UI에서 분석 챗봇 세션을 렌더링하고 대화 흐름을 제어한다.
def streamlit_chat(
    retriever: RagRetriever,
    df: pd.DataFrame | None = None,
    system_prompt: str | None = None,
    session_key: str = "analysis_chat",
) -> None:
    """Streamlit UI에서 분석용 챗봇 세션을 렌더링한다.

    매개변수:
        retriever: RAG 검색/응답 핸들러.
        df: 해당 분석에서 사용한 데이터프레임.
        system_prompt: 모델 역할 지시문.
        session_key: Streamlit state에 저장할 세션 식별자.
    """

    # st.session_state는 dict 구조를 허용하므로 분석 세션 컨테이너를 한 번만 초기화한다.
    session_store = st.session_state.setdefault("analysis_sessions", {})
    service = AnalysisChatService(retriever, session_store)
    # system_prompt가 비어 있을 때를 대비해 안전한 기본값을 둔다.
    prompt = system_prompt or "You are a security analyst assistant."

    if df is not None and session_key not in session_store:
        # 분석 DF가 있고 아직 세션이 없으면 최초 리포트를 만든다.
        with st.spinner("Generating analysis report..."):
            service.start_session(session_key, df, prompt)

    # Streamlit 챗 입력은 매 프레임 호출되므로 빈 값일 때는 아무 동작도 하지 않는다.
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
        # 과거 히스토리를 순서대로 출력해 사용자에게 맥락을 보여준다.
        for message in session.history:
            st.chat_message(message["role"]).write(message["content"])
