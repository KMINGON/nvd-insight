## cve
### CVE_ID
> cve -> vulnerabilities -> cve -> id
- cve 분류 id

### published
> cve -> vulnerabilities -> cve -> published
- 공개일

### last_modified
> cve -> vulnerabilities -> cve -> lastModified
- 수정일

### descriptions
> cve -> vulnerabilities -> cve -> descriptions
- CVE 취약점 설명
- en, es 여러 개 있어도 en만 있으면 됨

### metrics
> cve -> vulnerabilities -> cve -> metrics
- 심각도 점수들
- 

### cisaExploitAdd
> cve -> cisaExploitAdd
- CISA KEV 등재일
- 실제 공격에서 확인된(confirmed) 악용 사례가 있는 취약점
- 취약점 중 우선순위임, 분석 가치 높음

### configurations
> cve -> configurations  
- 영향 대상(제품/버전)
- 관련 CPE 정보
- `cpeName` 해석:
```text
cpe : CPE 스킴 고정 문자열
2.3 : CPE 버전
part = a : 애플리케이션(application)
vendor = progress : 벤더 명(Progress)
product = kendo_ui_for_vue : 제품 이름
version = 0.4.8 : 제품 버전
나머지(update, edition, language, sw_edition, target_sw, target_hw, other) = *
- *는 “모든 값(any)” 혹은 “명시되지 않음” 의미
```

### weaknesses
> cve -> weaknesses
- 연관 CWE 정보
- CWE ID
- 일단 Primary 에서 가져오고, Secondary가 있다면 거기에 해당하는 CWE까지 추가로 매핑


---

## CPE dictionary
### CVE별 영향받는 CPE 메타 정보 매핑
- 단순히 “영향받는 CPE URI와 그 메타 정보”만 필요
```python
cpeDictByName = {}  // key: cpeName (CPE 2.3 URI), value: CPE 메타데이터

for cpeRec in CPE_DICTIONARY_JSON.products:
    cpeName = cpeRec.cpe.cpeName
    cpeDictByName[cpeName] = cpeRec.cpe   // title, refs, deprecated 등 포함
```
```python
for cve in CVE_FEED_JSON.vulnerabilities:
    cveId = cve.cve.id
    affectedCpes = []

    for node in cve.configurations.nodes:
        for m in node.cpe_match:
            uri = m.cpe23Uri
            vulnerable = m.vulnerable

            cpeMeta = cpeDictByName.get(uri)  // 없으면 그냥 uri만 기록

            affectedCpes.append({
                "cpeName": uri,
                "vulnerable": vulnerable,
                "cpeMeta": cpeMeta
            })

    // 최종 CVE 묶음 JSON 생성
    cveUnified = {
        "cveId": cveId,
        "summary": ...,
        "configurations": ...,
        "cpe": affectedCpes
    }

    // 파일로 저장
```

---

## CWE
### ID
> Weakness (ID)
- CWE ID (고유 식별자), 예: CWE-1004
- 
### Description
> Weakness -> Description
- CWE 약점의 핵심 정의(짧고 요약된 설명)

### Extended_Description
> Weakness -> Extended_Description
- 약점의 자세한 설명
- 기술적 배경, 보안 효과, 왜 문제가 되는지 포함

### Background_Details
> Weakness -> Background_Details
- 약점에 대한 개념적/기술적 배경 설명
- 이 CWE를 더 깊이 이해하는 데 도움

