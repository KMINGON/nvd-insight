"""
Streamlit multi-page app package.

`Home.py` at the project root serves as the Streamlit entrypoint and delegates to the
renderers in :mod:`src.app.pages`. Chat-specific helpers continue to live in
``chat.py`` so other modules can import them with ``from src.app import chat``.
"""

__all__ = ["common", "chat", "pages"]
