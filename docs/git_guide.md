# Git A~Z 협업 가이드

Git을 처음 사용하는 사람도 그대로 따라 하면 협업에 참여할 수 있도록 단계별 절차를 정리했습니다. 아래 명령은 모두 프로젝트 루트(예: `cve_project`)에 적용합니다.

## 1. 저장소 클론

```bash
git clone <repo-url> cve_project
cd cve_project
```

원격 저장소 주소(`<repo-url>`)는 팀 Git 서버에서 확인하세요.

## 2. 사용자 정보 설정(최초 1회)

```bash
git config --global user.name "홍길동"
git config --global user.email "hong@example.com"
```

이미 설정돼 있다면 생략 가능합니다.

## 3. 원격(main) 최신 상태 동기화

작업 전에 항상 최신 코드를 가져옵니다.

```bash
git checkout main
git pull origin main
```

## 4. 개인 브랜치 생성

작업 단위(기능/버그)에 맞춰 브랜치를 따고, 이름에는 본인 이니셜이나 작업 내용을 간단히 포함합니다.

```bash
# 예시: feature/kim-add-rag
git checkout -b feature/<name>-<desc>
```

브랜치는 “작업 내용을 설명할 수 있는 이름”을 권장합니다.

## 5. 작업 및 변경 확인

코드/문서를 수정한 뒤 변경 사항을 확인합니다.

```bash
git status
git diff
```

## 6. 커밋 규칙

1. **작업 단위별로 작은 커밋**: 서로 다른 변경을 한 커밋에 섞지 않습니다.  
2. **커밋 메시지 형식**:  
   - `feat: 기능 추가`  
   - `fix: 버그 수정`  
   - `docs: 문서 변경`  
   - `chore/test/refactor` 등 Conventional Commits 스타일을 추천합니다.

커밋 예시:

```bash
git add src/dataset/build_dataset.py
git commit -m "feat: 연도별 JSON 출력 지원"
```

## 7. 작업 브랜치를 원격에 푸시

```bash
git push -u origin feature/<name>-<desc>
```

처음 푸시할 때 `-u` 옵션을 사용하면 이후엔 `git push`만 입력해도 됩니다.

## 8. Pull Request(PR) 생성

1. 원격 저장소(GitHub/GitLab 등)에서 방금 푸시한 브랜치로 PR을 만듭니다.  
2. 템플릿에 맞춰 변경 요약, 테스트 결과, 확인 요청자를 적습니다.  
3. 리뷰어의 코멘트에 맞춰 수정 후 `git commit --amend` 또는 추가 커밋을 푸시합니다.

## 9. PR 머지 전 최신 main 반영

다른 사람이 main을 업데이트했을 수 있으므로, 머지 전에는 최신 main을 가져와 충돌을 해결합니다.

```bash
git checkout main
git pull origin main
git checkout feature/<name>-<desc>
git merge main     # 필요 시 충돌 해결
git push
```

혹은 `git rebase main`을 사용해도 되지만, 익숙하지 않다면 merge가 안전합니다.

## 10. 머지 후 브랜치 정리

PR이 main에 머지되면 로컬/원격 브랜치를 삭제합니다.

```bash
git branch -d feature/<name>-<desc>
git push origin --delete feature/<name>-<desc>
```

## 11. 흔한 문제 해결

- **충돌(conflict)**  
  Git이 자동 병합을 못 하면 관련 파일에 `<<<<<<<` 표시가 생깁니다. 내용을 직접 수정한 뒤 `git add` → `git commit`으로 마무리합니다.
- **실수로 커밋한 파일 되돌리기**  
  아직 원격에 푸시하지 않았다면 `git reset --soft HEAD^`로 마지막 커밋을 되돌릴 수 있습니다. 이미 푸시했다면 팀과 상의 후 `git revert`를 사용하세요.

## 12. 주기적인 main 동기화 습관

긴 작업을 할수록 중간중간 main을 가져와 충돌을 최소화합니다.

```bash
git checkout main
git pull origin main
git checkout feature/<name>-<desc>
git merge main
```

---

위 절차만 따라도 Git을 처음 사용하는 구성원이 쉽게 협업 흐름에 참여할 수 있습니다. 문제가 생기면 `git status` 출력을 캡처해 팀에 공유하고, 명령을 실행한 순서를 설명하면 빠르게 도움을 받을 수 있습니다.
