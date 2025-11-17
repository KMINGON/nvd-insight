## 최종 데이터 예시
### 예시 데이터
```json
{
  "cveId": "CVE-2020-0601",
  "published": "2020-01-14T23:15:30.207",
  "lastModified": "2025-10-29T14:33:49.467",
  "description": "A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates...",
  "metrics": {
    "cvssMetricV31": [
      {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
          "version": "3.1",
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
          "baseScore": 8.1,
          "baseSeverity": "HIGH",
          "attackVector": "NETWORK",
          "attackComplexity": "LOW",
          "privilegesRequired": "NONE",
          "userInteraction": "REQUIRED",
          "scope": "UNCHANGED",
          "confidentialityImpact": "HIGH",
          "integrityImpact": "HIGH",
          "availabilityImpact": "NONE"
        },
        "exploitabilityScore": 2.8,
        "impactScore": 5.2
      },
      /* ... Secondary source 생략 ... */
    ],
    "cvssMetricV2": [
      {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
          "version": "2.0",
          "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
          "baseScore": 5.8,
          "accessVector": "NETWORK",
          "accessComplexity": "MEDIUM",
          "authentication": "NONE",
          "confidentialityImpact": "PARTIAL",
          "integrityImpact": "PARTIAL",
          "availabilityImpact": "NONE"
        },
        "baseSeverity": "MEDIUM",
        "exploitabilityScore": 8.6,
        "impactScore": 4.9,
        "acInsufInfo": false,
        "obtainAllPrivilege": false,
        "obtainUserPrivilege": false,
        "obtainOtherPrivilege": false,
        "userInteractionRequired": true
      }
    ]
  },
  "cisaExploitAdd": "2021-11-03",
  "cpes": [
    {
      "cpeName": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x64:*",
      "vulnerable": true,
      "criteria": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x64:*",
      "matchCriteriaId": "A045AC0A-471E-444C-B3B0-4CABC23E8CFB",
      "cpeMeta": {
        "deprecated": false,
        "cpeName": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x64:*",
        "cpeNameId": "4938AC37-7B3E-44A9-8021-84AA97101E0E",
        "lastModified": "2023-10-15T17:02:11.623",
        "created": "2022-12-13T17:56:11.167",
        "titles": [
          { "lang": "en", "title": "Microsoft Windows 10 1507 64-bit" }
        ],
        "refs": [
          {
            "ref": "https://learn.microsoft.com/en-us/windows/release-health/release-information",
            "type": "Version"
          },
          { "ref": "https://www.microsoft.com/en-us/", "type": "Vendor" }
        ],
        "deprecates": [
          { "cpeName": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x64:*" }
        ]
      }
    },
    {
      "cpeName": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x86:*",
      "vulnerable": true,
      "criteria": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x86:*",
      "matchCriteriaId": "28A7FEE9-B473-48A0-B0ED-A5CC1E44194C",
      "cpeMeta": {
        "deprecated": false,
        "cpeName": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x86:*",
        "cpeNameId": "9EBAA19A-DE95-479C-BA98-DC9709106CA4",
        "lastModified": "2023-10-15T17:02:11.623",
        "created": "2022-12-13T17:56:11.167",
        "titles": [
          { "lang": "en", "title": "Microsoft Windows 10 1507 32-bit" }
        ],
        "refs": [
          {
            "ref": "https://learn.microsoft.com/en-us/windows/release-health/release-information",
            "type": "Version"
          },
          { "ref": "https://www.microsoft.com/en-us/", "type": "Vendor" }
        ],
        "deprecates": [
          { "cpeName": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x86:*" }
        ]
      }
    },
    /* ... 추가 CPE 항목 ... */
  ],
  "cwes": [
    {
      "cweId": "CWE-295",
      "cweDescription": "Improper Certificate Validation",
      "cweExtendedDescription": "The product does not validate, or incorrectly validates, a certificate.",
      "cweBackgroundDetails": "A certificate is a token that associates an identity (principal) to a cryptographic key..."
    }
  ]
}
```

> **참고**: 레코드마다 `cisaExploitAdd`, `cvssMetricV2`, `cpeMeta`, `cweBackgroundDetails` 등이 없을 수 있습니다. 값이 존재하지 않는 필드는 JSON에서 생략되므로, 후속 코드에서는 `dict.get()`와 같은 안전한 접근 방식을 사용하세요.
### 컬럼 설명

- **`cveId` (string)**  
  - 출처: `vulnerabilities[].cve.id`  
  - 설명: 취약점을 식별하는 공식 ID. 예: `CVE-2020-0601`.

- **`published` / `lastModified` (datetime)**  
  - 출처: `vulnerabilities[].cve.{published,lastModified}`  
  - 설명: 각각 취약점이 공개된 일시, 그리고 NVD 기록이 마지막으로 수정된 일시입니다.

- **`description` (string)**  
  - 출처: `descriptions[].lang == "en"`  
  - 설명: 취약점 현상의 간단한 영어 설명입니다.

- **`metrics` (object)**  
  - 출처: `vulnerabilities[].cve.metrics`  
  - 설명: CVSS 3.x/2.0 점수를 그대로 담은 구조로, 위험도 계산에 필요한 모든 세부 필드를 포함합니다.

- **`cisaExploitAdd` (datetime, optional)**  
  - 출처: `vulnerabilities[].cve.cisaExploitAdd`  
  - 설명: CISA KEV 목록에 등재된 날짜. 실제 공격에서 사용된 취약점일 때만 값이 존재합니다.

- **`cpes` (array)**  
  - 출처: CVE `configurations` + CPE Dictionary  
  - 설명: 이 취약점의 영향을 받는 제품 목록입니다. 각 항목에는 제품을 식별하는 CPE URI와 제목, 참고 링크 등의 메타데이터가 포함됩니다.

- **`cwes` (array)**  
  - 출처: CVE `weaknesses` + CWE 카탈로그  
  - 설명: 취약점이 속한 CWE 유형 목록입니다. 각 항목은 CWE ID와 간단한 설명 및 배경 정보를 가집니다.
