## RAG 추가 수행 절차

기본 프로젝트 환경(가상환경, `pip install -r requirements.txt`, `.env` 구성 등)을 마친 뒤 RAG 기능을 사용하기 위해 추가로 실행해야 하는 명령만 정리했습니다.

### 1. 로컬 임베딩 모델 캐시 준비

네트워크가 허용된 환경에서 아래 Hugging Face CLI 명령을 실행하여 모델 스냅샷을 캐시에 내려받습니다.

```bash
source .venv/bin/activate
huggingface-cli download sentence-transformers/all-MiniLM-L6-v2
```

### 2. FAISS 인덱스 빌드

처리된 데이터(`data/processed/cve_cwe_by_year`)를 기반으로 로컬 임베딩 인덱스를 생성합니다. 진행률 표시를 보고 싶으면 기본 옵션 그대로 실행하면 됩니다.

```bash
source .venv/bin/activate
python script/build_faiss_index.py \
  --dataset-path data/processed/cve_cwe_by_year \
  --index-dir data/index/faiss \
  --batch-size 128
```

필요 시 `--embedding-backend openai` 등으로 백엔드를 덮어쓸 수 있지만, 기본 설정은 로컬 임베딩입니다.

### 3. RAG 기능 검증 (선택)

인덱스가 준비되면 Streamlit UI에서 챗봇 탭을 열어 벤더/제품 Top-N 요약을 로드한 뒤 질문을 입력합니다.

```bash
source .venv/bin/activate
streamlit run src/app/ui.py
```

OpenAI Chat 모델을 사용 중이라면 `.env`에 `OPENAI_API_KEY`가 설정되어 있어야 챗봇 응답이 생성됩니다.

### 4. 트러블슈팅 참고 사항

- **`sentence-transformers/text-embedding-3-large` 관련 OSError**  
  `.env`에 `EMBEDDING_MODEL=text-embedding-3-large`가 남아 있으면 로컬 백엔드가 OpenAI 모델 이름을 Hugging Face에서 검색하다 실패합니다. `EMBEDDING_MODEL` 값을 비워 두거나 `LOCAL_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2`로 명시하면 해결됩니다.

- **`AttributeError: 'NoneType' object has no attribute 'tokenize'`**  
  로컬 모델이 캐시에 없을 때 발생합니다. 1단계 스크립트로 모델을 다운로드하거나, 다운로드된 캐시 디렉터리를 동일 위치로 복사해 두세요.

- **`LangChainDeprecationWarning: HuggingFaceEmbeddings was deprecated`**  
  기능에는 영향이 없지만 경고를 없애려면 `pip install -U langchain-huggingface` 후 `from langchain_huggingface import HuggingFaceEmbeddings`로 교체하면 됩니다.

- **지속적인 인증 오류**  
  OpenAI 백엔드를 쓰려면 `.env`에 올바른 `OPENAI_API_KEY`가 필요하며, rate limit에 걸릴 경우 명령이 오래 걸릴 수 있습니다.
