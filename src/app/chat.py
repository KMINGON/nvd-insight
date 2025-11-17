from __future__ import annotations

from typing import List

import streamlit as st

from ..rag import RagRetriever


def streamlit_chat(retriever: RagRetriever) -> None:
    """
    Streamlit widget that proxies user questions to the RAG retriever.

    TODO: connect retriever.ask to a real LLM answer chain and render citations.
    """
    history: List[dict] = st.session_state.setdefault("chat_history", [])
    user_query = st.text_input("질문을 입력하세요", key="chat_input")
    top_k = st.slider("Top-K 결과 수", min_value=1, max_value=20, value=5)
    if st.button("질문하기") and user_query:
        try:
            answer = retriever.ask(user_query, top_k=top_k)
        except Exception as exc:  # pragma: no cover - UI feedback
            st.error(f"Retriever error: {exc}")
            return
        history.append({"role": "user", "content": user_query})
        history.append({"role": "assistant", "content": answer})
        st.session_state.chat_history = history

    for message in history:
        st.chat_message(message["role"]).write(message["content"])
