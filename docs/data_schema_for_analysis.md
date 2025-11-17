## 최종 데이터 예시
### 예시 데이터
```json
{
  "cveId": "CVE-2020-5179",
  "published": "2020-01-02T14:16:37.097",
  "lastModified": "2024-11-21T05:33:37.977",
  "description": "Comtech Stampede FX-1010 7.4.3 devices allow remote authenticated administrators ...",
  "metrics": {
    "cvssMetricV31": [ /* NVD 원본 그대로 */ ],
    "cvssMetricV2": [ /* NVD 원본 그대로 */ ]
  },
  "cisaExploitAdd": "2022-10-05T00:00:00.000", 
  "cpes": [
    {
      "cpeName": "cpe:2.3:o:comtechtel:stampede_fx-1010_firmware:7.4.3:*:*:*:*:*:*:*",
      "vulnerable": true,
      "criteria": "cpe:2.3:o:comtechtel:stampede_fx-1010_firmware:7.4.3:*:*:*:*:*:*:*",
      "matchCriteriaId": "E40F6E42-2191-4686-9631-81E8D134809F",
      "cpeMeta": {
        "deprecated": false,
        "cpeName": "cpe:2.3:o:comtechtel:stampede_fx-1010_firmware:7.4.3:*:*:*:*:*:*:*",
        "cpeNameId": "UUID-FROM-DICTIONARY",
        "lastModified": "2025-06-27T19:18:35.260",
        "created": "2025-06-27T19:18:35.260",
        "titles": [
          { "title": "Comtech Stampede FX-1010 Firmware 7.4.3", "lang": "en" }
        ],
        "refs": [
          { "ref": "https://vendor.example.com/", "type": "Vendor" }
        ],
        "deprecates": []
      }
    },
    {
      "cpeName": "cpe:2.3:h:comtechtel:stampede_fx-1010:-:*:*:*:*:*:*:*",
      "vulnerable": false,
      "criteria": "cpe:2.3:h:comtechtel:stampede_fx-1010:-:*:*:*:*:*:*:*",
      "matchCriteriaId": "41DFD1AA-89A6-4C33-A686-8A95EE45EDF9",
      "cpeMeta": {
        "deprecated": false,
        "cpeName": "cpe:2.3:h:comtechtel:stampede_fx-1010:-:*:*:*:*:*:*:*",
        "cpeNameId": "UUID-FROM-DICTIONARY-2",
        "lastModified": "...",
        "created": "...",
        "titles": [
          { "title": "Comtech Stampede FX-1010 Appliance", "lang": "en" }
        ],
        "refs": [],
        "deprecates": []
      }
    }
  ],
  "cwes": [
    {
      "cweId": "CWE-79",
      "cweDescription": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      "cweExtendedDescription": "Detailed explanation of how XSS works ...",
      "cweBackgroundDetails": "Background about web applications, scripts, etc ..."
    },
    {
      "cweId": "CWE-1004",
      "cweDescription": "Sensitive Cookie Without 'HttpOnly' Flag",
      "cweExtendedDescription": "The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies ...",
      "cweBackgroundDetails": "An HTTP cookie is a small piece of data attributed to a specific website ..."
    }
  ]
}
```
### 컬럼 설명
| 컬럼명            | 타입                          | 출처                                                             | 설명                                                   |
| -------------- | --------------------------- | -------------------------------------------------------------- | ---------------------------------------------------- |
| cveId          | string                      | `vulnerabilities[].cve.id`                                     | CVE ID (예: CVE-2020-5179)                            |
| published      | string(datetime)            | `vulnerabilities[].cve.published`                              | CVE 공개일                                              |
| lastModified   | string(datetime)            | `vulnerabilities[].cve.lastModified`                           | CVE 마지막 수정일                                          |
| description    | string                      | `vulnerabilities[].cve.descriptions` 중 `lang == "en"`의 `value` | 영어 설명만 1개 선택                                         |
| metrics        | object                      | `vulnerabilities[].cve.metrics`                                | CVSS v3.1 / v2 점수 묶음 (원본 구조 그대로)                     |
| cisaExploitAdd | string(datetime) (optional) | `vulnerabilities[].cve.cisaExploitAdd` (있을 때만)                 | CISA KEV 등재일. 실제 공격에서 악용이 확인된 취약점. 없으면 필드 생략 또는 null |
| cpes           | array                       | CVE `configurations` + CPE Dictionary 조인 결과                    | CVE와 연관된 모든 CPE(취약/비취약 포함)의 매핑 결과                    |
| cwes           | array                       | CVE `weaknesses` + CWE 카탈로그 조인 결과                              | CVE에 매핑된 CWE 약점 리스트                                  |
