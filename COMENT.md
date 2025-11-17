# 추가 코멘트
- 현재 `data/processed/cve_cwe_dataset.json`이 170k개 CVE를 한 번에 담기 때문에 파일이 약간 크다. 후속 분석 단계에서 메모리 부담이 있다면 JSON Lines 형태 혹은 연도별 샤딩을 고려하면 좋다.
- `src/dataset/build_dataset.py`는 전 데이터를 메모리에 적재한 뒤 덤프하므로, 추후 증분 빌드를 지원하려면 제너레이터 기반 스트리밍 처리와 임시 파일을 사용하는 편이 안전하다.
- RAG 인덱싱 파트(`src/rag/indexer.py`)는 아직 미구현 상태이다. 추출된 `cpes`, `cwes`, `description`을 결합하여 문서 청크를 구성할 때 토큰 수 관리 전략을 미리 정의해 두면 LangChain 체인 구성 시 시행착오를 줄일 수 있다.
- Streamlit UI(`src/app/ui.py`)에서 retriever를 즉시 생성만 하고 로드하지 않는 상태이므로 FAISS 인덱스를 마련한 뒤 `RagRetriever.load()` 호출 위치와 에러 처리를 정리해야 한다.
