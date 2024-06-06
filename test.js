import { printRecursiveObject } from "./services/print.js";

const sonarqube = {
  name: "",
  description: "",
  vulPath:
    "fix/CVE-2020-15092/NUKnightLab/TimelineJS3/184/cd4d0c60ca1eaad164bdf7935ffab2eb7a68459d/TL.Media.js",
  lineNumber: 64,
  scope: {
    start: 64,
    end: 64,
  },
  type: "VULNERABILITY",
  key: "AY-lio4Q7zmieQwcvrtO",
  rule: "secrets:S6334",
  severity: "BLOCKER",
  message: "Make sure this Google API Key is not disclosed.",
  effort: "30min",
  tags: ["cwe", "owasp-a3", "sans-top25-porous"],
  quickFixAvailable: "no",
  properties: {},
};

const snyk = {
  name: "",
  description:
    "Unsanitized input from the request URL flows into Function, where it is executed as JavaScript code. This may result in a Code Injection vulnerability.",
  vulPath:
    "fix/CVE-2019-8903/totaljs/framework/176/c37cafbf3e379a98db71c1125533d1e8d5b5aef7/index.js",
  lineNumber: 16999,
  scope: {
    start: 16999,
    end: 16999,
  },
  type: "",
  key: "be9f2675333b265bc2cc5f52caf798da7cab117a849c7193775f86deba45c820",
  rule: "javascript/CodeInjection",
  severity: "error",
  message:
    "Unsanitized input from {0} {1} into {2}, where it is executed as JavaScript code. This may result in a Code Injection vulnerability.",
  effort: "",
  tags: [],
  quickFixAvailable: "no",
  properties: {
    priorityScore: 801,
    priorityScoreFactors: [
      {
        label: true,
        type: "multipleOccurrence",
      },
      {
        label: true,
        type: "hotFileSource",
      },
      {
        label: true,
        type: "fixExamples",
      },
    ],
    isAutofixable: false,
  },
};

const codeql = {
  name: "Inefficient regular expression",
  description:
    "A regular expression that requires exponential time to match certain inputs can be a performance bottleneck, and may be vulnerable to denial-of-service attacks.",
  vulPath:
    "fix/CVE-2017-1000427/markedjs/marked/5/cd2f6f5b7091154c5526e79b5f3bfb4d15995a51/marked.js",
  lineNumber: 459,
  scope: {
    start: 459,
    end: 459,
  },
  type: "",
  key: "",
  rule: "",
  severity: "error",
  message:
    "This part of the regular expression may cause exponential backtracking on strings starting with '*' and containing many repetitions of '**'.",
  effort: "",
  tags: [],
  quickFixAvailable: "no information",
  properties: {},
};

const mergeFormattedResult = (result1, result2) => {
  return {
    name: [result1.name, result2.name].filter((name) => name).join(" - "),
  };
};

// console.log(mergeFormattedResult(codeql, sonarqube));
// console.log(mergeFormattedResult(codeql, snyk));
// console.log(mergeFormattedResult(snyk, sonarqube));

const results = [];
const result1 = { name: "azeem", similarResult: [] };
const result2 = { name: "azeemSimilar", similarResult: [] };

results.push(result1);
const index = results.findIndex((result) => result.name === "azeema");
if (index >= 0) {
  results[index].similarResult.push(result2);
} else {
  results.push(result2);
}

printRecursiveObject(results);
