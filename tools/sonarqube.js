import { log } from "../services/logger.js";
import { makeDir, writeFile, readFile } from "../services/file.js";
import { getSingleLineFromString } from "../utils/text.js";

const baseUrl = `http://localhost:9000/api/issues/search?projects=${process.env.SONAR_QUBE_PROJECT_KEY}`;
const API_LIMIT = 10_000;
const pageSize = 500;

const headers = new Headers();
headers.append(
  "Authorization",
  "Basic " +
    btoa(
      `${process.env.SONAR_QUBE_USERNAME}:${process.env.SONAR_QUBE_PASSWORD}`
    )
);

export class Sonarqube {
  querySonarQubeServer = async (url) => {
    return fetch(url, {
      headers,
    });
  };

  fetchResultsFromServer = async (issueType) => {
    let totalIssues;
    try {
      const response = await this.querySonarQubeServer(
        `${baseUrl}&types=${issueType}`
      );
      const responseJson = await response.json();
      totalIssues = responseJson.total;
    } catch (err) {
      log(`Error!, while fetching sonar qube issues - error trace: ${err}`);
    }

    let issues = await this.fetchIssuePages(issueType, true);
    if (API_LIMIT < totalIssues && totalIssues <= 2 * API_LIMIT) {
      issues = [...issues, ...(await this.fetchIssuePages(issueType, false))];
      const issueMap = new Map();
      for (const issue of issues) {
        issueMap.set(issue.key, issue);
      }
      issues = [...issueMap.values()];
    }

    await this.createFormattedOutput(issues);
    return issues;
  };

  fetchIssuePages = async (issueType, inAsc) => {
    let issues = [];

    for (let i = 1; i <= API_LIMIT / pageSize; i++) {
      try {
        const response = await this.querySonarQubeServer(
          `${baseUrl}&types=${issueType}&ps=${pageSize}&p=${i}&asc${inAsc}`
        );

        if (response.ok) {
          const sonarqubeData = await response.json();
          if (sonarqubeData.issues.length > 0)
            issues = [...issues, ...sonarqubeData.issues];
          else break;
        } else {
          log(
            `Error!, while fetching sonar qube issues of page ${i}, where page size is ${pageSize} - ${response.statusText}`
          );
          break;
        }
      } catch (err) {
        log(
          `Error!, while fetching sonar qube issues of page ${i}, where page size is ${pageSize}  - error trace: ${err}`
        );
        break;
      }
    }

    return issues;
  };

  createFormattedOutput = async (issues) => {
    const formattedResults = [];
    await makeDir("./formattedResults");

    for (const issue of issues) {
      const formattedResult = {
        name: "",
        description: "",
        vulPath: issue.component.split(`${issue.project}:`)[1],
        lineNumber: issue.line,
        scope: {
          start: issue?.textRange?.startLine,
          end: issue?.textRange?.endLine,
        },
        type: issue.type,
        key: issue.key,
        rule: issue.rule,
        severity: issue.severity,
        message: issue.message,
        effort: issue.effort,
        tags: issue.tags,
        quickFixAvailable: issue.quickFixAvailable ? "yes" : "no",
        properties: {},
        similarResults: [],
      };

      formattedResult.foundVulLine = getSingleLineFromString(
        readFile(`${process.env.FILES_BASE_PATH}/${formattedResult.vulPath}`),
        formattedResult.lineNumber
      );

      formattedResults.push(formattedResult);
    }

    writeFile(
      `./formattedResults/formattedResult-sonarqube.json`,
      JSON.stringify(formattedResults, null, 4)
    );
  };
}
