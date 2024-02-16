import { createNewLogFile, log } from "../services/logger.js";
import { makeDir, writeFile } from "../services/file.js";
import { nanoid } from "nanoid";

const baseUrl = `http://localhost:8000/api/issues/search?projectKey=${process.env.SONAR_QUBE_PROJECT_KEY}`;
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

createNewLogFile();

export class sonarqube {
  fetchResultsFromServer = async (issueType) => {
    const totalIssues = (
      await (
        await fetch(`${baseUrl}&types=${issueType}`, {
          headers,
        })
      ).json()
    ).total;

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
      const sonarqubeResponse = await fetch(
        `${baseUrl}&types=${issueType}&ps=${pageSize}&p=${i}&asc${inAsc}`,
        {
          headers,
        }
      );

      if (sonarqubeResponse.ok) {
        const sonarqubeData = await sonarqubeResponse.json();
        if (sonarqubeData.issues.length > 0)
          issues = [...issues, ...sonarqubeData.issues];
        else break;
      } else {
        log(`Error: ${sonarqubeResponse.statusText}`);
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
        vulPath: issue.component.split(`${issue.project}:`)[1],
        lineNumber: issue.line,
        scope: {
          start: issue?.textRange?.startLine,
          end: issue?.textRange?.endLine,
        },
        type: issue.type === "VULNERABILITY" ? "VULNERABILITY" : "",
        key: issue.key,
        rule: issue.rule,
        severity: issue.severity,
        message: issue.message,
        effort: issue.effort,
        tags: issue.tags,
        quickFixAvailable: issue.quickFixAvailable,
      };

      formattedResults.push(formattedResult);
    }

    writeFile(
      `./formattedResults/formattedResult-${nanoid()}.json`,
      JSON.stringify(formattedResults, null, 4)
    );
  };
}
