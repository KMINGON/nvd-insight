# 1\. 프로젝트 개요

\- 프로젝트명: NVD 기반 취약점 수집·정제·분석 및 API 제공 시스템

\- 팀명: NOyhsA==

\- 팀원: 김민곤, 김기남,박찬진,서유진,정현학

\- 프로젝트 기간: 2025-11-17 \~ 2025-11-21

본 프로젝트는 **NVD(National Vulnerability Database)** 와 **MITRE**에서 제공하는    
**취약점(CVE), 관련 제품(CPE), 취약점 유형(CWE) 데이터**를 **수집·정제·분석·시각화**하여    
제공하고, LLM RAG 기술 기반 자동 리포트 생성 서비스 제공을 목표로 한다.

## 2\. 프로젝트 배경 및 목적

### 2.1 배경

 매년 대량의 취약점 정보가 공개되지만, 해당 데이터는 CVE·CWE·CPE 등 전문 형식으로 제공되어 일반 사용자나 소규모 조직이 활용하기 어렵다. 특히 NVD·MITRE의 JSON 데이터 구조는 복잡하고 지속적으로 변경되며, 데이터 규모도 방대해 효과적인 인사이트 도출이 쉽지 않다.  
이러한 문제를 해결하기 위해 **데이터 수집·정제·구조화**, 그리고 **누구나 이해할 수 있는 시각화 및 AI 기반 분석 리포트**가 필요하다.

### 2.2 목적

- NVD/MITRE 취약점 데이터를 전체 자동 수집하고, 정제·정규화된 형태로 구축  
- 벤더·제품(CPE), 취약점 유형(CWE), 위험도(CVSS) 기반의 직관적인 시각 분석 제공  
- 복잡하고 방대한 취약점 정보를 정규화된 데이터셋과 직관적 시각화로 제공해, 데이터 활용 진입장벽을 크게 낮춤.  
- 사용자 맞춤형 필터와 통계/그래프로 보안 입문자, 동아리, 연구자, 실무자 모두 각자의 상황에 맞는 데이터 인사이트를 즉시 얻을 수 있음.  
- AI 챗봇 및 자동 요약 리포트 기능으로, 비전문가와 교육/실무 현장에서 쉽고 빠른 보안 트렌드 파악과 커뮤니케이션 지원.  
- 개발팀, 보안팀, 연구기관, 교육 강사 등 다양한 사용자 페르소나에게 산업별, 제품별, 유형별 위험 패턴 및 관리 전략 자료를 자동 제공하며 실질 사용성을 높임.

### 2.3 예상 인사이트

- **연도별·분기별 취약점 발생 트렌드 분석**: 증가·감소 추세, 특정 시기 집중 발생 여부  
- **벤더/제품 취약점 분포**: 특정 벤더나 제품군에서 취약점이 집중되는 패턴 탐지  
- **CWE 기반 취약점 유형 상위 랭킹**: 어떤 취약점 유형이 빈번하게 발생하는지 파악  
- **심각도(CVSS) 기반 위험 포트폴리오**: 고위험(High/CRITICAL) 취약점 비중 및 변화 추이  
- **신규/제로데이 특성 분석**: 급증하는 특정 취약점 유형 및 관련 공격 벡터 식별  
- **취약점-제품 상관관계 지도화**: 동일 제품군에서 반복되는 취약점 유형 시각화  
- **패치/업데이트 지연 위험 구간 식별**: 취약점 공개 후 패치 적용까지의 평균 소요시간 분석  
- **AI 기반 요약 및 위험 해석**: 데이터를 기반으로 한 자동 리포트(트렌드 요약, 리스크 시나리오 등)

## 3\. 주요 기능

###  3.1 필수 기능

1\) 데이터 정제 및 전처리

- NVD/MITRE에서 수집한 취약점·제품·취약점 유형 데이터를 다운로드하고, 중복·누락·불일치 정보를 제거해 표준화된 구조로 통합한다.  
- 비정형 JSON 구조를 정규화하여 분석 가능한 테이블 형태로 변환한다.

2\) 데이터 분석

- 연도별 트렌드, CWE 유형별 분포, 벤더·제품(CPE) 기반 취약점 통계, CVSS 심각도 분석 등을 자동 수행한다.  
- 제품군별 위험도 패턴, 특정 취약점 유형의 증가/감소 등 인사이트 추출이 가능하다.

3\) 시각화 데이터 제공

- 그래프·차트·히트맵 등 직관적인 시각 자료를 통해 취약점 현황을 한눈에 이해할 수 있게 제공한다.  
- 벤더/제품별 취약점 지도, CWE 유형별 발생 비율, 시간 흐름에 따른 위험도 변화 등을 시각적으로 표현한다.

4\) AI 요약 리포트 및 챗봇 질의 기능 제공

- 분석된 취약점 데이터를 기반으로 자동 요약 리포트를 생성해 주요 트렌드와 위험 포인트를 설명한다.  
- 사용자가 질의하면 취약점 현황·종류·위험도·관련 제품 등 정보를 AI 챗봇 형태로 실시간 응답한다.

## 4\. 기술 구현 요구사항

### 4.1 Python 기반 데이터 수집 및 전처리(pandas, numpy)

### 4.2 matplotlib/seaborn 등 데이터 시각화

### 4.3 LLM 기반 취약점 설명 요약 기능

## 5\. 기대효과

### 5.1 학습 효과

- **보안 데이터 표준 이해**: CVE·CWE·CPE·CVSS 등 취약점 데이터 표준 구조와 활용 방식 이해.  
- **데이터 파이프라인 구축 능력 향상**: 대규모 JSON 기반 보안 데이터를 수집·정제·정규화하는 실습 경험 확보.  
- **데이터 분석 역량 강화**: 취약점 데이터의 트렌드 분석, 통계 기반 인사이트 도출 경험 축적.  
- **시각화 역량 향상**: 보안 지표를 직관적인 차트·지도·대시보드 형태로 표현하는 능력 향상.  
- **AI 활용 능력 강화**: 분석 데이터 기반 자동 리포트 생성, 챗봇 질의 응답 모델 구성 등 생성형 AI 적용 경험 습득.  
- **보안 인텔리전스 관점 이해**: 취약점 증가 패턴, 고위험 제품군, 유형별 반복 발생 등 보안 인텔리전스 기본 개념 체득

### 5.2 실무 적용 가능성

- **보안팀 취약점 관리 자동화**: 신규 취약점 발생 시 트렌드 파악, 위험도 우선순위 산정 등 업무 효율 강화.  
- **개발팀 보안 품질 개선**: 자사 제품·기술 스택과 관련된 취약점 유형을 파악하여 보안 취약 코드 예방 및 설계 개선에 활용.  
- **운영팀 패치 전략 수립**: 고위험 취약점 우선 패치, 반복적으로 발생하는 유형 모니터링 등 실무 운영 의사결정에 직접 활용.  
- **연구기관·교육용 활용**: 보안 분야 학습자 또는 연구자에게 실전형 분석 데이터셋과 시각화 자료 제공.  
- **위협 인텔리전스(TI) 기초 시스템으로 확장 가능**: 패치 지연 분석, 공격 벡터 분석 등 고급 TI 시스템의 기초 인프라로 확장 가능.  
- **경영진 보고 자료 자동화**: AI 리포트를 통한 요약 보고서 자동 생성으로 의사결정 자료 마련   
  시간 단축

## 6\. 유저 페르소나 및 사용 시나리오

### 6.1 **대학생 보안 연구/동아리**

- 기본 정보  
  - 이름: 김예나  
  - 나이: 22세  
  - 신분: 대학교 3학년(컴퓨터공학과)  
  - 관심 분야: 데이터 분석, 정보보안 입문, 보안 동아리 활동  
  - 프로젝트 주제: 보안 데이터 기반 시각화 / 분석 프로젝트  
- 사용 목적  
  - “보안 데이터를 분석해서 과제나 팀프로젝트에 활용하고 싶지만, NVD·CVE 데이터 구조가 너무 복잡해서 어디서부터 시작해야 할지 모르겠다.”

  - 데이터 양이 많고 스키마도 어렵고 전문 용어도 많아서 데이터를 어떻게 다뤄야 할지 감을 잡고 싶다.

  - 특히 전처리·정규화·필드 의미를 빠르게 파악해서 자신이 할 프로젝트의 방향성을 정하고 싶다.

  - 팀원에게 설명하거나 발표해야 해서 “한눈에 보여주는 대시보드”가 꼭 필요함.

- 계략적 묘사  
  - 김예나는 정보보안에 흥미가 있지만 CVE/NVD 같은 복잡한 스키마를 이해하기 어려운 보안 입문자이다.

  - 코딩은 가능하지만 데이터 전처리 경험이 부족해 필드 구조 파악에 시간이 많이 걸린다.

  - CVSS·CWE·CPE 등 전문 용어가 많아 보안 데이터를 읽는 데 부담을 느낀다.

  - 팀 프로젝트에서 시각화 파트를 맡았지만, 어떤 데이터부터 다뤄야 할지 몰라 어려움을 겪는다.

  - 발표와 결과물 품질을 위해 **사용하기 쉬운 요약·정규화된 데이터**가 꼭 필요하다.

- 사용 시나리오  
  - **팀플 시작 & 데이터 수령**  
     NVD JSON을 받았지만 필드가 너무 복잡해 어디부터 분석해야 할지 막막함.

  - **원본 데이터 확인 후 좌절**  
     중첩 구조와 낯선 용어들(CPE·CWE·CVSS) 때문에 Pandas로 불러오는 것조차 부담됨.

  - **발표 일정 압박 증가**  
     팀플에서 데이터 정규화를 반드시 해야 해서 스트레스가 커짐.

  - **대시보드 도입**  
     정규화된 CSV와 핵심 필드 설명을 한눈에 제공받으며 빠르게 구조를 이해함.

  - **필터링 기능 활용**  
     클릭 몇 번으로 특정 벤더·연도·위험도 데이터만 골라 팀플 자료로 바로 적용함.

  - **시각화 결과 공유**  
     추이·분포·Top10 그래프가 자동 생성되어 팀원 전체가 쉽게 이해함.

  - **발표 자료 제작 단축**  
     대시보드 결과를 그대로 가져와 PPT를 빠르게 완성함.

  - **자신감 상승 & 긍정적 피드백**  
     시각화 파트를 무리 없이 수행하며 “보안 데이터도 할 만하다”는 자신감을 얻음.

### 6.2 보안 교육 강사

- **기본 정보**  
  - 이름: 박정우  
  - 나이: 38세  
  - 신분: 보안 교육 강사(기업 보안 트레이너/외부 교육기관 강사)  
  - 관심 분야:웹 취약점 분석, 침해사고 대응, 보안 컨설팅  
  - 프로젝트 형태: 데이터 기반 시각화 / 분석 프로젝트

- **사용 목적**  
  - “최신 취약점 동향을 교육에 반영하고 싶은데 CVE·CWE·CPE 데이터가 너무 많고 구조도 복잡해서 수작업으로 정리하기에는 시간이 너무 많이 든다.”

  - 교육 자료를 최신으로 유지해야 하는데 NVD JSON 구조가 복잡해 실습·슬라이드 제작에 부담이 큼

  - 필드 의미(CVE ID, CVSS, CWE, CPE)를 빠르게 이해하고 강의용 그래프·요약 자료를 효율적으로 만들고 싶음

  - 기업 교육에서는 특정 기술 스택 관련 취약점만 요구하는데 필터링·시각화가 매번 수동이라 시간이 오래 걸림

  - 강의 중 학생 질문에 즉시 답하기 위해 한눈에 보여주는 취약점 요약 자료가 필요함

- **계략적 묘사**  
  - 박정우 강사는 실무 경험이 풍부하지만, **매일 쏟아지는 취약점 데이터를 직접 수집·정리하는 데 많은 시간을 소모한다.**

  - 복잡한 NVD JSON 구조 때문에 **강의 자료용으로 바로 가공하기가 쉽지 않다.**

  - 강의마다 최신 통계(CWE Top10, 월별 추이, CVSS 분포 등)가 필요한데 **슬라이드 제작 시간이 과도하게 걸린다.**

  - 학생들의 질문에 대응하기 위해 **즉시 CVE 개요·영향도·관련 취약점 정보를 확인할 수 있는 자료가 필요하다.**

  - 효율적으로 최신 데이터 기반 강의를 준비할 수 있는 **자동 분석·요약·시각화 도구가 절실한 상황이다.**

- **사용 시나리오**  
  - 박정우 강사는 “최근 1년 웹 취약점 트렌드 분석” 교육을 준비하지만, NVD JSON이 복잡해 초기 분석부터 큰 시간이 든다.

  - CVSS·CWE·CPE 등 복잡한 필드를 직접 해석해 그래프화하는 작업이 1\~2일씩 걸려 비효율을 느낌.

  - 교육 일정이 촉박해 매년 바뀌는 취약점 트렌드를 수작업으로 갱신하기 어려운 상황에 놓임.

  - 프로젝트 대시보드를 사용하며 정규화된 CSV와 핵심 필드 설명을 바로 확인하고 필요한 데이터만 빠르게 추출함.

  - 필터(웹 서버만, HIGH만, 특정 연도만)를 활용해 강의 슬라이드용 차트와 표를 즉시 생성함.

  - 대시보드에서 월별 추이, CVSS 분포, CWE Top10 등 주요 그래프를 얻어 빠르게 교육 자료를 완성함.

  - 강의 중 학생 질문에도 CVE 상세 정보를 즉시 확인해 바로 대응할 수 있게 됨.

  - 전체 강의 준비 시간이 크게 줄고 최신 트렌드를 반영한 완성도 높은 커리큘럼 구성 가능.

### 6.3 보안 입문자/학생

- **기본 정보**  
  - 이름: 김00

  - 나이: 20세

  - 신분: 국내 4년제 대학 컴퓨터공학과 재학생

  - 역할: 보안 동아리 신입

  - 관심 분야: 해킹 기초, 웹 취약점, CTF 입문

  - 프로젝트 형태: 취약점 트렌드 기반 학습/연습용 분석 프로젝트

- **사용 목적**  
  - “보안을 공부하고 싶은데, CVE·CWE·CVSS 등 개념과 데이터 구조가 너무 복잡해서 무엇부터 공부해야 할지 우선순위를 정하기 어렵다.”

  - 최신 취약점 동향을 기반으로 중요 취약점을 먼저 학습하고 싶음

  - CTF나 실무에서 자주 등장하는 취약점 유형을 한눈에 정리된 자료로 보고 싶음

  - 초보자도 이해 가능한 수준으로 정제된 데이터와 시각화된 정보가 필요

  - 복잡한 NVD JSON 구조 대신 핵심만 뽑아주는 분석 도구가 필요

  - 학습 계획 수립에 도움이 되는 간단한 필터링·정렬 기능을 원함

- **계략적 묘사**  
  - 김00은 보안에 막 입문한 대학생으로, 이론은 배우고 있지만 실제 취약점 데이터를 보는 건 처음이다.  
  - NVD나 CISA 사이트에서 제공하는 정보는 용어가 어렵고 구조가 깊어 이해하기 부담스럽다.  
  - 선배들은 최신 취약점 분석, CTF 문제 풀이, 실무 기반 리서치 등을 하고 있지만, 김00은 현재 그 수준을 따라가기 어려운 상태다.

- **사용 시나리오**  
  - 김00은 동아리 프로젝트와 개인 학습을 위해 취약점 트렌드를 파악하려 하지만,  
     NVD 데이터를 열어보자마자 복잡한 필드 구조에 막혀버림.

  - CVSS, CWE, 공격 벡터 같은 용어가 익숙하지 않아  
     어떤 취약점이 중요한지, 어떤 걸 먼저 공부해야 할지 판단하기 어려움.

  - 원본 JSON 구조가 중첩돼 있어 초보자가 보기에는 난이도가 높아  
     학습 방향 설정조차 어려운 상황에 놓임.

  - 대시보드를 사용해 정규화된 필드(CVE ID, CVSS, CWE, 공격 유형 등)를 간단히 파악하며  
     초보자도 이해할 수 있는 형태로 핵심 정보만 빠르게 확인함.

  - 필터 기능으로 자신에게 맞는 학습 자료를 직접 선별함

    - 최근 취약점만 보기

    - 웹 취약점(XSS/SQLi)만 보기

    - 위험도 높은 순 정렬

  - 시각화된 그래프를 통해 학습 우선순위를 직관적으로 도출함

    - CWE Top10 → 가장 자주 등장하는 취약점 파악

    - CVSS 분포 → 위험도 감 잡기

    - 연도별 추이 → 최근 유행 취약점 확인

  - 정리된 데이터를 기반으로 개인 학습 루틴을 설계함  
     → “이번 주는 XSS, 다음 주는 RCE를 공부해야겠다.”

  - 최종적으로 데이터 기반으로 학습 방향성을 얻게 되고  
     CTF·보안 공부를 본격적으로 시작할 수 있게 됨.

7\. 시각화 참고 자료

![][image1]

![][image2]

Streamlit으로 구현하기 위해서는 네비게이션 함수를 이용해 선택한 모듈이 실행되는 구조로 레이어 잡는 방법 있음

탭(레이드) 형식으로 나누면 싱글쓰레드 기반 streamlit에서 구현하기 쉬울 수 있음

[image1]: <data:image/png;base64,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>

[image2]: <data:image/png;base64,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sU9uFcAu+k5zn7jse611zL4ELURExLXpoEHLff372ma02oPWRVL2xDMELURERFxZLnPQys1+XN/ftKBVbi9ms55YobNaBC1ERMS16UwErdUuQQsREXFtOkjQMn//0qOlGy5obl9LLjRoPfPML7Knn34GERFxRfqL537ZGNvW2jhnz9Ge62BBCysXErT0hUJERFyJetBQdb/VrLUBQWtoT58naCEi4ppUx7i1OM4RtAZW20sbVNUXCBERcaWqY9xaHOcWHbQIW+2+4qT/1WgrbVBVXyDzS39za/bn1+xrlB+rDybKtPzBL+zM/uz8nY19EBER+6pjXNs458699n/m69/Kl/c9/Z3GPub2176mftzbvpRt/1ZzP/W+RNnQLknQwv5qg6r6AsUBqzVsPXBjdv75Fwd1275LmmFJg5bv4+W32/okaJ1P0EJExEWoY1xqnDMtKM3NzfUKWq/56HfKoPWauTPL4zVo1cJYWV/z3Iv1/vt/WFuqBK2R1QZV9QWKw9Xev7ypsX2aFpz+7Pyrw/r5k+X/KIJTHLQsVOlxiIiIS6GOcalxbvtr58IyhK0iaNnSgpMGrfs+moenrqBlgerMYtu++PhofSm98ca/bZS5BK2R1QZV9QUyLWxZyGqb0fLZrNydk0AVP27OctVmtG7Pg1ij/GkLaTvDbJkFNA9piIiIfdUxrm2ca1ODltt26/A1NisWqccNFbSmSdAaWW1QVV8gRETElaqOcWtxnCNojaw2qKovECIi4kpVx7i1OM4RtEZWG1TVFwgREXGlqmPcWhznCFojqw2aci38aQJERFy98id4lvBP8ODC1AZFRETE1StBa2S1QREREXH1StAaWW1QREREXL0StEZWGxQRERFXrwStkdUGRURExNUrQWtktUERERFx9UrQGlltUERERFy9ErRGVht0mmd8Kst+7SLE4X39R7Ps7+4/2uiDffzpT3+aHT58GBERJ9p7YvweSdAaWW3QlK/6YJY9/izi+Frf0/7Ypr2hAABAGnuPtPdKgtbIaoOqZ+9tDn6IY2p9UPul+rOf/UzfUwAAQHjiyacIWmOrDarqoIe4HGq/VAEAoJsnn3ySoDW22qCqDniIy6H2SxUAALo5evQoQWtstUFVHfAQl0PtlyoAAPSDoDWy2qCqDnju733oaHbxXx3N3rXnxey4jS82tuPaMTt0aMnUul3tlyoAAPSDoDWy2qCqDnjuN3+YZX9x20vZY89kIWgRttamGpSWQj2Hqf1SBQCAfhC0RlYbVNUBz73ngfpjgtbaVEOS+dNtr6s9vn7bHcl9DnzG1pvb9Bym9ku1F4lrPSYfe0xrzh555BEtWjKGrBsAFsZzzz2nRTPDU089pUVJCFojqw2q6oDnErTQrAJIFZgsRH33La8oH1dB63Nl2dVv+Vyxz0hBS86xaJ9/vqz6+Wh9KAhbAMuPfZB81ulzjQStkdUGVXXAcwlaaMbh48DLX5Fd/aoPlTNa+YxVfUbr+pdXASz3juxqKdNzmNov1U6i+u18dm22tMCXfebMfH2iX7utf3ey9MB4x6vOlOs+VFbd54dSD378hLDcOfn/ZtP+LDvh4wcb2+KyubMOBNs4d+vF2Y1HJitHbgrrvgzrBUf278p231vtb+yeLO0w4+491b6G72Pl5+65Jy8rlgCweiBojaw2qKoDnuufy3JPfDdBay36/E8eawaQRWj16TnCeRJ9M7aTxLksbN3xqteFoOVlFrRCWfH4jtsmZbZcUNCqAtLc3FyphSxbLkXQMm68dFcIWEYIT/furW03LDTdeOnFYX3b/vl8eWlxTLT/7q278uW9RV0ZQQtgtULQGlltUFUHPET16aeeb4aQY9Dq0bpd7ZdqJ4nzWdA68PJm0Ipve4aZrld9aEFBy4OVceCsfOlhyrcrccjy9a6gdbf9pwhagSI42azVuSFM5cGqFrSKfUKA8vXJ/gQtgOXhhPL94mBZZu8b8fuE71OVHSgfT3+XSEPQGlltUFUHPMTlUPul2omGpMXKZ7QAIMv/4XTllVdqcfmPLJvBNsP63Am1f1QZJ5y4s1g7WPsHWhy05sp9nGOJVxUErZHVBlV1wENcDrVfqr3QsHSs8q1DAJhw5plnalGJBy2jb9CaRjwrvlgIWiOrDarqgIe4HGq/VAEAxuZXf/VXsze/+c2lMXHQim/7adCqOFiuLW6+qhuC1shqg6o64CEuh9ovVQAA6AdBa2S1QVUd8Mx9f3xBWG7/TpZ9a8epednEb4Vtx5f7rVufr9t+/njdG6+q1eX7mH/0Za8/L7PlH63P60/p9cbuk7ra9ktp57PriY99/DtX5dc90eoOdX05f/7rwrXNl8/B2yKsN+qfb7SN6/XF+/q21+2YL8tftz7f74+iNlsrar9UAQCgHwStkdUGVXXAi9030YPTuiIEeJiwxx4I4qCjQSsOH3HA8dCiQSsOKHFIU+PttaAVBae2OuLrqIWjP761PWiVZUXoiurT8+17tgpN29+YClpNX1fUa9dA0GraxcFMpvLtG337N4X18lt+/uHTonxT7Vs+OVbm6Daf+m+d9i/qjSl/2qH4nIZd17TPYsTPwdj08Z2N6/DbFMHim4v58mC53bGfnDD8MyQx8XONv+V0MCp14nOmOKgFACuQRx99VItmjj7XSNAaWW1QVQe83FvLdQ9YFgA8DFhwaAsxfYNWFUyaM1qNur9T1bmv3G++CDvzUVmuhbi8jijgRNdcm9ESa7Nzch1xmc5oWdtYed/ZtXBMNJul9eu+q13tl2o/qgjUCF0P7KwCThSIdp6YDg4B3++BPOx4sEkFrYPRei0ImZOQ1TdoxYTnMLkGDTd+vIUnD1p+TRasDhbrtl/8zagupu2TClr2lXQ/78GyFACWG4LWyGqDqjrgmR4aqtmsYrZFQoDPvMS31NS2oNVqOfvjQSpbcNAqw17LTNK062gGpSoMxSFSg5YfV4bR2MZ1VEE2JTNaTbs5UAz2+X89YHgwCPM9iYDTK2gtgto3k4qgkgpqSvPr3s7Beojr+C2uhZCa4Ys5YW7x7QEAw0PQGlltUFUHPMTlUPul2oXGjTDzJLfh4qA1bfamJApacbipneuBKhClglx1DQerQglw8XHJ4Bedw7GvkRupoHUwsabP14+P8d/2SYWtg9n0oHVQCwBg2SBojaw2qKoDHuJyqP1SXdMcc9Aaj4NaAADLBkFrZLVBVR3wEJdD7ZcqAAD0g6A1stqgqg54iMuh9ksVAAD6QdAaWW1QVQc8xOVQ+6UKAAD9IGiNrDaoqgOeeeHFO7PLr7gmaOvxtnO3Xpxcml+L9nv/l/Jv6+3YuqtR/9c+eXHtOETtl2oX23fsCX3KBQBYqxC0RlYbVNUBz7SB6oa//lowHYjuyff7ZL78/sT3T9ZTQeuvPtwMWn/14YvLYxFN7ZdqF5++5notirgny47cFNbunnjupTdlN+6xx/fkmyfbjpT75v0/Zz7sG+Pbzt1THAsAMGMQtEZWG1TVAc+Mw1UtaD10U22/OFjp46lBa7LNwpaW49pV+6XaxfSgZf14V+bB6u49eVjaFkLTfFiPg5aXGdskaPmxxm5mzgBgBiFojaw2qKoDHuJyqP1S7WJq0Cpms4wwo7XnnklI2lttzwhaALB6IGiNrDaoqgMe4nKo/VLt4vCPf5L937+/rxQAYK1C0BpZbVBVBzzE5VD7pQoAAP0gaI2sNqiqAx7icqj9UgUAgH4QtEZWG1TVAc/93kOPNMqWyiHrxpWp9ksVAAD6QdAaWW1QVQc8c4wgNMY5cOWo/VIFAIB+ELRGVhtU1QGvt/s2leuv3n4wm9t0oHpcrJ/x2vzHTj9vZXObwrJRD+KzBC0AgKWCoDWy2qCqDnhpD5brc3NzpWfsyx8TtHCxar9UAQCgHwStkdUGVXXAS+nBytb/YfsJeXkxo2WPbds/yDGvLkKWGQcurRvR1H6pAgBAPwhaI6sNquqAZ47x+akxzoErR+2XKgAA9IOgNbLaoKoOeO6QQWjIunFlqv1SBQCAfhC0RlYbVNUBD3E51H6pAgBAPwhaI6sNquqAh7gcar9UAQCgHwStkdUGVXXAQ1wOtV+qAADQD4LWyGqDqjrgIS6H2i9VAADoB0FrZLVBVR3wzFNOv7BY7pp4dvAzDxTb3rUvLD9U7OPep/XctissbwmP7yqOyctSer3u5mt/HJZ+3rLsgfp+KW/507Mny/z4UPef5udvXGNhfA7Tr9Ovoa+br90X2sqP/cy78nV1c7GPGtrqgbwOs9le+fNw7fXJn2tVFp5L2Ub59d937YXJa/Fr/dBt9XJV22ezvPZhn6L+/PWu6rTnoK9tSu2XKgAA9IOgNbLaoKoOeO59RVDKB8tqYI2Dlg3UHl5s6QN3sE/QKvYJwUKDVvG4VqcZBS0/d2OfYBWSLIyk90n7oeLcU4OWBL4QeIqQVJVPOT7SgpAt42MtHDbaqxG0LlxU0PIw5G3vAU+vo3ZMsc1CXlxur4W91h608np2hf31tU2p/VIFAIB+ELRGVhtU1QGvtAxaMrjHM1oSejTMpAZuDxVqPBj7jJqFBp1N0XNqPRYu9JxthhAQ7efhLg44bXVpuT7X9hmtu/L9fJYtag8PKaE+CVoaeGLT5zGrtmjbJz5nm332MfNz5dfMjBYAwPJA0BpZbVBVB7wwYJYzHNWtw+r2Uj54+76tM1o120OC2zYYl0ErmmGbbnMWqS0oeN3+HJpBq+W6p92+7LhOv22oM1GhTB43Z7TUu8JtvEYYTdgWtGJT19RXn+nS50/QAgAYF4LWyGqDqjrgIS6H2i9VAADoB0FrZLVBVR3wEJdD7ZcqAAD0g6A1stqgqg54wdqHuqvbZ16mt7jc/BZc8bmg1Ie55Zab3UaLP9fjtynt801Wl31+KVnXbfktTVv3cj/Wy+1WmR8bf7A+Pp9rZeE5Rbe96rfRmt9g9LoazxGPSe2XKgAA9IOgNbLaoKoOeJUeLvJgsbkIFP7tsmq/u8rHrUFrErDCZ7w0aPm3+6Kwct/keA9aXmb1a9Dy9TJoyeeAPvOu6kPmfh49Jq4rBCv/FqTvP7ne/PNPzaCVrAuPWe2XKgAA9IOgNbLaoKoOeK6FnXx2qPmB8F4zWqfbV/sthEQfTo+DVjEr5YafBpiEHQtFcdAqv8WWCEeNctF/lkKDlj7ulqA1tNovVQAA6AdBa2S1QVUd8JrWb5WF326KtuvPNcThyUNItY/8VITNeiV+LFNntMy2QBOXx7f74usIwSoR7Hxfn/2qfqi12k/P1xa02sIn9lP7pQoAAP0gaI2sNqiqAx7icqj9UgUAgH4QtEZWG1TVAQ9xOdR+qQIAQD8IWiOrDarqgIe4HGq/VPvy+ONPZY8++gQmBIC1AUFrZLVBVR3wEJdD7ZdqHzxQPPnkz7OjR1/SzQvG6rC6NLCsZJ977pf6NAFglUHQGlltUFUHPMTlUPul2oUHiaHQwLKSBYDVDUFrZLVBVR3wEJdD7ZdqF2MECA0sK1WbpQOA1QtBa2S1QdWz9zYHPcQxtT6o/VLtwgJEzAkn7sxXHiiWE3Y+kC/nzjpQlp3w8YP5crJ/XG7oYw0suZ/PHr3uD8P6vR9+TVhef+ZcbZ/LvjnxhNeU+/n2P7huckyjvspXz81lc8H8uJpFXZWfbylPnwMAVi8ErZHVBk35f+5vDn6IY2h9T/tjyi40PJxQhpS58rGHrq6gNechTdCwUgacRLiJPdag9eg3P5pdb2q5Kef0kGfltv9lJ9TDngoAqxeC1shqg7Z5yq580NOBEHEIf/izLHvLn/cLWWYXqfBw4Kw8ZBWPyuDVGbSigBajYSW3HrTsOAtQup+Vv/rD32qUTw1axXFmXJaq3+r5A9svuhYLXH8wVwQwEQBWLwStkdUGRVyJdqHhQW/7xaS2xUHLt3oIczSs5DZvHYbAE+9TbO+aZVoSO2bXzMcee7L2vABgdUHQGlltUMSVaBcWIJ544mktXjKsbg0sK1UAWN0QtEZWGxRxJdrFCy+8GELEEGHL614tAsDqhqA1stqgiCvRPqy2QLTU8rMOAGsDgtbIaoOmfObZX2TPPfecvlYAg2N9T/tjSgAA6AdBa2S1QVUb6ACWkz5hCwAA+kHQGlltUBVgFtB+qQIAQD8IWiOrDaoCzALaL1UAAOgHQWtktUFVgFlA+6UKAAD9IGiNrDao2sZxG18svfbvXtLNAFn288NZ9ti3F2YL2i9VAADoB0FrZLVB1Ta+dzhf3v/wS9lzv8yya75K2IKIF55phqi+JtB+qQIAQD8IWiOrDaq2cf/D+ayWsf0LR8t1gMBj95XB6frdN4fld4v17777ZdnVr3rZpCwvz778nwhaAAAjQdAaWW1QtQ0LWmddcTT4zivzW4gAJVFwslBletDyMgtavm2MoDX/ePOPVyMirhbtPa4PBK2R1QZV2/AZLfNfnkXQAmHKjNaBL1u5lY03o0XIQsS1YJ+wRdAaWW1QtY1zrjwabhm6BC2oMWOf0dI3I0TE1WoXBK2R1QZVAY6ZGfrWob4RISKuVrsgaI2sNqgKMAtov1S70DciRMTVahcErZHVBlUBZgHtl2oX+kaEiLha7cKClarvqbEErUWqDaoCzALaL9Uu9I0o9tGfZ9l/+cjRRjki4kq0Cw1ZBK2B1QZVAWYB7ZdqF/pGFGtf5Nh310uNcvcdX8mXr/ytPfnj3/pYWL7h6h9n3756z6T8+sYxiIjLZRcasghaA6sNqqZ4aPeptcdXPDjxpONrZX25RR+f5/XcGv4bznXzBdUOEdW+PZnUs2798dmG3fPhvA8VxVbmOuHxSVfV9ttgZefl16VUbVJt9/q8bWyZn+eCxnPaXJzfrk235dvrbW77O+EYW0bPo+06VyraL9Uu9I3IveorVcCywKXbH//BV8p1C1W2fOWZeZkFLC9DRJwVu9CQRdAaWG1QNYWFCh/ILTxY0FoM9eCWhwYLUZtvtvBQDxgxCw5aWXVMV9Byqv2mB5d15XXm+3kQsrAWh1ALQx64WkkErQ0WziI8mJXhTEiVrWS0X6pd6BuRe+K7q3D106ez7PtHmvu88gN/H5Y+s4WIOMt2oSGLoDWw2qBqijwYVcHDZ7TiWRQLKB5qQuiYhIcwe/XgVaEsDlc6Q2YhwUKW1RmOiYPHg1VwCfUX9fk2uy4LZ5sTs0aGh8I4aBl6DY7uVztfQRzUrnhweiBrI8xyOYnr1qDVRtnmN8uGFY72S7ULfSMyUzNYm3Yu7LNazGgh4qzZhYYsgtbAaoOqKTyUlLfGiqAV387KbwnmocOC0xXnWUCpZlmmBYtyBshDjQQtfxyf368pBBILY3ZN59Vnk2I8QMUzQ7n1a2kErRZStw6d+BpshiuQCFPTzlMLWpPnV7/mPHBq2bT6VhraL9Uu9I3IPfD/Xqp58GfNfRARV5JdaMgiaA2sNqi6WukboPru1zdowbGh/VLtQt+IEBFXq11oyCJoDaw2qAowC2i/VLvQNyJExNVqFxqyCFoDqw2qAswC2i/VLvSNCBFxtdqFhiyC1sBqg6oAs4D2S7ULfSNCRFytdqEhi6A1sNqgKsAsoP1S7ULfiBARV6tdaMgiaA2sNqia4tD8kezju68J2jrA0Gi/VLvQNyLzlg+eFpZnnLylLDtjz3y5vuHkHWH53mi7HePHpfzuni3ZpzadFszrzuuI3fDBO8N+8Tkq76zqknpDfdH1ubfIY/NTm6prbjtO1WPM9xbX58/Z2iJuD/WMTTfU65wct+Hkor2+V21LtaG1xXsbv1WWX7eXW13BSRs29632K+v8oLVn3qYbimt7b+J6asfIc2g95ivFa+dLLe8qe7Zqh+q1rl5/u474tbXX0PqT7xuea3E9cV8Jj4v+0jyvtWfUx3y/qEyN+3C+Xq/D/NT36v8feZmfY9p5qm0t/SK8htHj8Prk/SK+Nus/cT+P+4LvF7+22ldWk11oyCJoDaw2qJri3K0XZ3994GtBW2+S/4zDtv358u6JR/bvDUvHt9146a6oNOfcPfdM/msC5Gi/VLvQNyL3jD3VG6+HIzcOWmcUA3wctMoAEdknaFX1W53tg3Q8eNqgZfunAlMjaDUGV/POMqA0t9Utw0yhDUjdQStR7yQEWDt4O5WD3eQaUgNqSm9HHxRD4CnCRWqg9MHd9Ta0NvJBNm4D3T9sTwStVLvFbVQLxc/Ww7lp50/1BX8OcdDy11mDltehocrKtaxsm7IvxNdfrdt++fNtPr+UGybPK389m/v3DVpluxXt3BW0tM97m+ThrtmmLkGrHQ1ZBK2B1QZVU8ThSoNWHJIsTJ27dW+5zYKW769BK64n37a6ftkcFof2S7ULfSNyq6DVDDD1Ga18exW05hsDQLv1QSkePDVo2eDhsyc2eMaDkOnnzMuLa4q2L5VeZzyQ2TlT4TJlaj8fRO05pgZUH4C13CxntIrAE8JMNFB6my1FW6SCVlBm5DSQpvZbuOkZLQs4edhvBi0zVRashW6vW2aIimDXOPZZbU/bx42us+gjfYKWtplft/ezuF+U4b5HIIr7qZ+XoNWOhiyC1sBqg6op7Hahz2hx6xDGQPul2oW+EZk+QNQHzfpgEQ+gtt41o+Xq7FibGrRiy9mYRCiJ1XCRmn2ZNqiUISYahFJBq5wRmnLNqQE7df1aVrXXfDI0pK4/Vdb0zhAAbKBPXVvK1qB1jPtNs7wlmZiF1BktMzWjZWrZ9GuLZrSK85fX0cvmrUNTg5Zbn9GarvaLtPP59U7azPt6KmjFpma+vP9oG68Gu9CQRdAaWG1QFWAW0H6pdqFvRIiIq9UuNGQRtAZWG1QFmAW0X6pd6BsRIuJqtQsNWQStgdUGVQFmAe2Xahf6RoSIuFrtQkMWQWtgtUFVgFlA+6Xahb4RISKuVrvQkEXQGlhtUDXFE088oUUAg6L9Uu1C34gQEVerXWjIImgNrDaomuKFF9Llyqb99cdzc3P1ggk/+clPtAiggfZLtYu7ftR8M0JEXG3ae10XGrIIWgOrDap2sWluU1geOGsuO6DboqC188QTwtL2icsPHz5cPQBoQful2ofbD06C/dPNNyZExJWuvbfZe1wfNGQRtAZWG1TtYu6sIl7tzwNX+bgnBC3og/ZLFQAA+qEhi6A1sNqgagq9dei3BG2ptwu74NYh9EH7pQoAAP3QkEXQGlhtUDUFH4aHsdF+qQIAQD80ZBG0BlYbVAWYBbRfqgAA0A8NWQStgdUGVQFmAe2XKgAA9ENDFkFrYLVBVYBZQPulCgAA/dCQRdAaWG1QFWAW0H6pAgBAPzRkEbQGVhtUXdv8WAuyc07fpUUdeB131Uqncd3DWpJzyo7+dRwrh+TxdVsvlJI2tK1+nB264ViPbaL9Uu3LLecdn6076apa2brzbs2uOOn4Wtnm9f741lpZVQ4AsDLRkEXQGlhtUDXF9tPzAbQrdGzvmQtu33F27fE5N3QPvIZfh3HdVq+j37HK7dG6BZr8mvK6vG67Ln/O208/OztlYnxcCtvnlK37Mg1aeZmRl3tbWX12TJ18owetUGewHmT8Wsr2e3hfYx/Dr92JX0cPWudMjrN1D1oe/ppB7OxaWxl2fqu/T9DKr7n7NdN+qfbBAlVYFkHLQle5rRag5qP1av+Hsjxs1fcFAFhZaMgiaA2sNqiaZDKAZ3ftCupges4kQJhGGbRs/8JQZusR+UCd72wDuQ3UVfiqh50yTEzOEQctIw8v+f7bJ+HBr8PQgGCE8FBcSy1oTY7LA0YVAKpw0x4uq32qEGbmbdRMnRowHZ3R8scLndGysKRtbZTXuID62sNvHqqq4HZX8Xw7ZrSs/ywA7ZfqQtAZLUNntCxUldx8QfbQ7lPDKjNaALDS0ZBF0BpYbVC1DZ8F0cHawo2HIgtVFjTKx2Gm6MJikK0G7lTQqgbidNDaPtknvq113dY8+MVBKxxTBI04aFlwuc5mXSbXo/XWqa5Rg1rbrFI1I+QzX4lAMbnOeijblQxEira1Bk2jFhiL+lMhSZ+P4+Ved/etw2bdORq0poW6tjoqtF+qx8rmm7XEma/NXG3Ync9yMaMFACsdDVkErYHVBlUBZgHtlyoAAPRDQxZBa2C1QVWAWUD7pQoAAP3QkEXQGlhtULWLQy23faoPp7eTvK2Wos/neRr7TLtVBSsN7ZcqAAD0Q0MWQWtgtUHVJEWoCR/0bnzWKv98jwUt+yxU+EC2kfgMkgYt/TyQfV4o1BmFKPugevWNvSjkEbRWNdovVQAA6IeGLILWwGqDqin8Q84WpHRGy7995jNa9Q9958f5B8DjoGXhSYPX9tOLn08oQlTjA+QErTWD9ku1D08//bQWDQ5/gB0AZg0NWQStgdUGVdvwQKVByym/aej7Rd9Aq7bVg1Yb5bYyTCVClISx5D6wYtF+qc4yzz//vBYBACwbGrIIWgOrDap20RW0yt9ZSgQpncFS7GcJvJ7wW1LRzyI0YEZrVaP9Ul0Ix218MXvnN6vHf5u9FMri7T+y8ivzst+ePN5ddHPdz7frtt/+4kvl+uHDh8t1AIDlRkMWQWtgtUFVgFlA+6V6LLzTAtUXLRzVg5YRgtbE4648Gh5b0Np94YvhGCc+xoOYBSzXIWgBwCyhIYugNbDaoCrALKD9Ul0ou0OAOlrMbFWhKMZCloUt06mCVh7ALJB5yIohaAHArKIhi6A1sNqgKsAsoP1SnWX4jBYAzBIasghaA6sNqgLMAtov1T7wrUMAAILW6GqDqgCzgPZLFQAA+qEhi6A1sNqg6i9/+Ut9jQBGxW69ab9UAQCgHxqyCFoDqw2qPvPsL/Q1AhgV64PaL1UAAOiHhiyC1sBqg6YMAx0f6IVloE/IMgEAoB8asghaA6sNirgSBQCAfmjIImgNrDYo4koUAAD6oSGLoDWw2qCIK1EAAOiHhiyC1sBqgyKuRPuwbv0F+fK8W8uyDbvnw/Kh3aeWZYGb832NW6JiO3bd+uOzdSddFZUCAKwcNGQRtAZWG7TNRx55JHvuuef09QIYhBdeyPuc9sM2u7jipOPDcvPN9aDl4asRtBJYwCrXCVoAsELRkEXQGlht0KR84xCWiT6/oWX2YYPNREVhacP6Klz1CVpZVsxmMaMFACsYDVkErYHVBlX/6Z/+SV8jgFF57LHHGv1S7cMVD+ZLv10Yo0FLHysELQBYqWjIImgNrDaoCjALaL9UAQCgHxqyCFoDqw2qAswC2i9VAADoh4YsgtbAaoOqbTz4SJZ9/TsvBWGNY5/hO3Ro8U75LKD2SxUAAPqhIYugNbDaoGob353PA9b9D7+UnfaRo7IV1gyPPdYMTIvR6kug/VIFAIB+aMgiaA2sNqjaxvcOZ9mX7nopOzrJW8dtfDEIaxANSkthAu2XKgAA9ENDFkFrYLVB1Tbuf7j+mKC1RtGQNPGn215Xe3z9tjuS+xz4jK03t6XQfqkCAEA/NGQRtAZWG1Rtw4LWWVccDb7zyqMErbWKhqQyaH2ufFwFrSpUXf3yVwTHC1r2kw7FzzrctiNX2PD2G7KNJ8fld1bbLqnWrZ4NJ58WDNuKpXF475Z826Qu5bM/0pJ0GQDAkGjIImgNrDao2oZ9NiuGoLVG0ZC0FCbQfql2EoWrz759S3Ah1ANRPWhV2/IwVgtak3P69jiQeegjaAHA2GjIImgNrDao2kb8rUO+ebjG0aC0GFvQfql2kYerPGjZ7NTGvc0fLW0nns1qkgpLHrQOh/9qqKoHNQCAMdGQRdAaWG1QFWAW0H6pjs22kxMzYonbkTEetDZGASsV0gAAhkRDFkFrYLVBVYBZQPulCgAA/dCQRdAaWG1QFWAW0H6pAgBAPzRkEbQGVhtUBZgFtF+qAADQDw1ZBK2B1QZVl5rNN2tJzkNakGDdebdmVzyopYljH7xKS0oe2n2qFk24VQsK5rMrTjo+X53UuW798cG259BGfH15HRdEJd1sWH9qtu6k+nMq62x5ro02WeFov1QBAKAfGrIIWgOrDaqm2LC+CB/Ft6nK8BPCSB5kNrSEiTKk3Jxvv+W8vK62YOD1WNAog1bXscV2x0OKBZw4aPm1atCqQk0UtCLK5xCFHA2At0Trfn1+vUlaApPV2zdo5dd6awhzjTZZ4Wi/VAEAoB8asghaA6sNqqbJg8nmInBZGAgBphj0LWRo0PKQ4SElnikypgUDCw5hWQStacf6vrbNw45f54bd8+E6rdzL8gDTHrTK+iLiYNkoK7Br9SAaX1987pgrTooDYL7drz8VtBRvXw+P09pzJaL9UgUAgH5oyCJoDaw2qNqGBQkfzBvBY7KMg1Z8qyy+7WaBwsPEtGBgdYVbbtGtw6nHtswOGfGMVhWOJGgVtwhvkRmttluGGrIUv77q3HqrsnqsodHaLhW0bD8NszGNNlnhaL9UAQCgHxqyCFoDqw2qLjVtYWVaMChvHy7xZ7Q8UKVmrXL6Ba0umuEp9TmxdlJBq+vaG22ywtF+qQIAQD80ZBG0BlYbVAWYBbRfqgAA0A8NWQStgdUGVQFmAe2XKgAA9ENDFkFrYLVBVYBZQPulCgAA/dCQRdAaWG1QFWAW0H6pdrFx7w3ZhpN3TNwS/qj0NvujzsUffm5D/55h+APR8vcMwx+otjonddl6KIvq3XZbuRo9vjP8Qenb65tKbr/ktGzbXqtjPvvs3ul/PxEAYKFoyCJoDaw2qNrGP973/SDAGGi/VLuwgBOchC0POKmgZQEotiwvQlQ6aFmAO+2Yg1YIcFlRv6//qKij4w9VAwAsFA1ZBK2B1QZVU5y79eIyaNl6xT3RepbdeCRf5ov57O6i/Mj+Xdm2/fYbU/PZtkt3FaWTevfck+3euiu7e09VBmBov1SPhVTQMjRkWT9NhS/D6thos1nRjJb/fpqhQasMUBPaZrQAAIZEQxZBa2C1QdUUcbiqB60J9+7NPHBZcPJ1C1ketIw8aE3CWBS0wvZwvJVLvbCm0X6pHgsetDburYJRPIOUDGItM0xtQatBFLQAAJYDDVkErYHVBlVTtAatIzdV61k9WOnjVNDKZ7T2ZjdOthG0IEb7pQoAAP3QkEXQGlhtUBVgFtB+qQIAQD80ZBG0BlYbVAWYBbRfqgAA0A8NWQStgdUGVQFmAe2Xai+Kz1fZzyco1eermnz2R1pSlcUfkE/t5+TfLKzvX342rPjc1uG99Z+TMKr965/70g/lV8c2Px9m+/q54mu0n7qIidul9YP6RRt+9u3FlwPC59iqc5bf6JTrs/2d+LNvvp/99Ibiz93azr9UELefHxOXlV8+uC3/KQ9rl/jcRq2O6FrK10g/mxd9ri71utc+41fDy9u/TDGd/Dgj7p/extqP43PodZqp17RZ1vz/ILRp8bpXz7Xar2y3Kf8PpZ5/qqz5Gcaq7Qy93rINov+3bV//dq+TPNeEjV4+ec3jfuLr9o1ix37GxSif54/sJ2OK4xPP3c8V16HE5/T94utsfJlmidCQRdAaWG1QFWAW0H6p9sHf1HSAMtoHy3SA8jf8+I1Q38QN+zkJwwcjwwNCn6BVUQ265fXYG73/pMTJHqbqz0PrtGOtHcoBazJA+XVsfHs1IOiAZthz0Pry51Wd0wcJPT4VtOKfw0gFLSMODCVFe8XH+CDor4cvU0HLyM+ZD7BOW9Cy432bBhijve9U5TagGxpu87JmAAjlRfvYOeM29eed6sdOeZ0aGq2sOF/VZyriOlPX6vuH44vrK9stqldf/4pmYIzR10T7sx7jz8Hbr94m3UErbHt7/jxrfbTYLw5JXpYKVdqO/hysH8YBqtxerCeDVvT8CVqrRG1QtY1HHnlEiwbhhRdeyJ544gkthjWG9ku1i+pNbn7qALUYUoFMsR9KdfI35/w3tdoGgqosfyO34NC2f/6m3Rz0w34yaDeV2a3aowSTsFOFx+Y5p9E3aPkgY9ccDzhV2GkGjj5BKw69TrimYlYkHuj0WA1a9jgeZLVdPQRoWYyXN2nOaNVmthL92H9ktwpl1Xm7+mf1XDteT5l1srrDDwCLSucsk/yDIxUStV96e3odCw1a5T96Tq76iS/zkJS3m1+LbUu1pb6mhp9rwTNaBK3VpzaommKskBXz/PPPaxGsIbRfqr2YcuuwQfkzDvPVwBzdKijf8KOfe9A3xfI8jdshOf7mPO16qjqrN3I7t/5qvZ67DR8gkmEjGsTrA0nVBjpQ5fi11UOjUtYRDSS+Xypoxc+5DDjRNVbHVPuV7RBuHe5IBq18W3GdxbXoTF2Mz5a1kRpkdXCd1i59SM2ipPqN9osU8bVoYEiFGw8X5tQZrcQ1xqT6aON6E/+vxO3bDFp5O/tr7LcO8+dRvx59TRxtg1BW1Nd3RitFGfa9IHr/SJ1Tbx3a80612VKgIYugNbDaoGoXBz9+QljuPDFf2uO5ublgyf5N2YGzosfCCcX+B7Oqvk37s+xAtM/hw6mhAdYK2i/VhZAaoJaD1AA9NKk3+MWz+OeRD5j9BjAnHc7qJIPWEpN6HdsG9YU+R6fv4L4czO478+LbLPU69nkt4lmxvv9/pM5F0FolaoOqXfQKWhP6Bi3DjyVogaP9UgUAgH5oyCJoDaw2qNoXD1oeskyblcosPu3flIenYlkPYgcaZQeLLTEErbWN9ksVAAD6oSGLoDWw2qBqCj6jBWOj/VIFAIB+aMgiaA2sNqjaxlhhi28dgqH9UgUAgH5oyCJoDaw2qAowC2i/VAEAoB8asghaA6sNqgLMAtovVQAA6IeGLILWwGqDqgCzgPZLFQAA+qEhi6A1sNqgKsAsoP1SBQCAfmjIImgNrDaomuL2HWdrUSeHbrgwO+X0hR+nLLqOu3Zl1229sFZkdZ5zw49rZW2ccnp+7Pa7ZMOE67aePdm+S4sDh7RgwjlFXfprx16ux6TOWdvn4X3huaTaSMvD870rv1YvP2VHfoLtxXOw55I/n3Tb6PXF+LV2tet1D+f9ydpuGtovVQAA6IeGrCULWhddc3P2pmJ9x2Rdt69VtUHVFDYwWnAK60WZDajm9mgwP2XrvnylGNCLB+G/dlwY4B/O97GB2QbdcEzY3wfoerrwIBP2t8G5rDuu18qaqcTDRhy0ymvM8jq3R0HKnqOdw8u8vNrXnmsVJKogk5flQaRat/axtiv3K4JRAyn369aw1E7zuSsaCn3d2sODVnhta69FnTKgJa7P1z1oxW0Yc47tNwl4BC0AgHHQkHVMQWvHJVuyN13SDFNnfOKGcv2i809vbF+LaoOqKXxG61AISflAaoOlhQkPYKGsDDHRQF0EIwsqPoPieNgKSICKKfex9TI0VUErhKFauMvRMGDEA3wctIzwXCbPMZ5J8gCWuv6Anbc8d/W8Q9sU63G4S9OsN4SeLD1DNG1maSH4OTxo2fPIy+rnDG04eQ56Xg1L5+jzLEJ1Cj1W0X6pdiJ/Q83/CG6dO8s/JxL/MeCK9J/SsD9r0/anbcq/5Vb+TcT87wGGbbfJbGZ0jfHfgCv/5Ef0dxXjx+Fv0U32if9OXXn9tT8XUp3b/96fYcv4OurHVH+wN2wr1vO/KVddoz2XPn8SBwCWHw1ZxxS0fuWtn8zOeGOzfMsnLivXU9vXotqg6moinm2Zbe4qA2EZziQgxmjgOVaqIKohtRnuDD1vV1iaRtex2i/VLqo/GlwPSx6sHAtgplP/I7v1Y+Ng0R60qmBTcWe20c7TN2gl68jPGf/dRn2Obddkz9m3+flrf5Q38bfcbH//W2x2vLdbvrxT/iZb83gAmB00ZB1b0MLeaoOqALOA9kv1WLCw02R+yh9yTQctn9FKBZQyyEUzWo4GLZ9Bc21Wyq8lXKvOaIXyepnV5yEtGbSKMFcGrFrgyp9f6nnYdg+dtu6zaB7a/DqT5wSAmcKC1eWXX15K0BpYbVAVYBbQfqkulLbbXCFkFIEmtU8enIpAIkHLiGeYfJYohBu5dejhpDaj5bcC28KKBK0ws1TOYuVY8PLjG/VEx1uIS60bqaAVQp8G06g+D1plsASAmcWC1bXXXhtCli2POWjZB97ts1r+2D4MH24XvvWT2a9PHm+ZPN7yVt9WfXYr+UH5yTFatuOauKw6z0pTG1Rtwz8nVX5zLvomYm3wyOqfqfLbUFZ2TnSLyj4U7cR1hdtT0Wd79BuDsDbQfqnOPInZqEbQ6kKDloSs5SYVTAFg9tDbhscUtM44f0v4huGbiiDlXvSJy0K42lKEpHy5pfqQ/Burz3CZ/i3FELTibW/cEuoKAS2EsDUYtIrP1PjndBYbtGKmB61qG6wdtF+qAADQDw1ZxxS0fv38T9Z+zsHcUXwQ3r5teNElk6BUhK0w89WYxZLgFAUtmw2zbzSGoBW+uWj7rt6ghYiIiGvXZNAa15UbskxtUERERER3BoLWylYbFBEREdElaC1SbVBEREREl6C1SLVBEREREV2C1iLVBkVERER0/z9ywK/KTLqU1QAAAABJRU5ErkJggg==>