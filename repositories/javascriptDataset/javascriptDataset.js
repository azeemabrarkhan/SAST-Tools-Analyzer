import {
  csvToArray,
  writeFileAsync,
  makeDir,
  writeFile,
} from "../../services/file.js";
import { fetchFile } from "../../services/http.js";
import { log } from "../../services/logger.js";
import GenerativeAI from "../../services/generativeAI.js";
import {
  getFunctionsInHierarchicalStructure,
  getInnerMostVulnerableFunctions,
} from "../../services/functions.js";
import {
  getLinesFromString,
  removeLinesFromString,
  removeTabsAndNewLines,
} from "../../services/text.js";

const initialAIPrompt = `Code snipets are needed to be analyzed for vulnerability detection. Snipets will be supplied continously. They are needed
  to be checked for vulnererabilities. Do not provide long answers for every input, instead just provide a detailed summary in the end regarding 
  the types of vulnerabilities or issues found in the code snipets. Please also include CVE and CWE, if possible.`;

const finalAIPrompt = `All of the code snippets have been provided, now please provide the required summary. 
  Please also mention the total number of snipets provided, the vulnerable and the clean snipets.`;

export default class JavascriptDataset {
  currentDir;
  datasetFilePath;
  downloadedRecordsFilePath;
  statsFilePath;
  aiChatHistoryPath;
  downloadedRecords;
  shouldAnalyzeRecordsWithAI;
  generativeAI;

  constructor() {
    this.currentDir = process.cwd();
    this.datasetFilePath = `repositories/javascriptDataset/records.csv`;
    this.downloadedRecordsFilePath = `${this.currentDir}/repositories/javascriptDataset/downloadedRecords.json`;
    this.statsFilePath = `${this.currentDir}/datasets/javascriptDataset/stats.txt`;
    this.aiChatHistoryPath = `${this.currentDir}/datasets/javascriptDataset/aiChatHistory.txt`;
    this.downloadedRecords = [];
    this.shouldAnalyzeRecordsWithAI = false;
    this.generativeAI = new GenerativeAI();
  }

  async scrape(shouldAnalyzeRecordsWithAI) {
    this.shouldAnalyzeRecordsWithAI = shouldAnalyzeRecordsWithAI;
    const dataset = await csvToArray(this.datasetFilePath);
    const formattedDataset = this.getFormattedDataset(dataset);

    if (this.shouldAnalyzeRecordsWithAI) {
      console.log(`Initial prompt to the AI: ${initialAIPrompt}\n`);
      const initialResponseFromTheAI = await this.generativeAI.chatWithAI(
        initialAIPrompt
      );
      console.log(
        `Initial response from the AI: ${initialResponseFromTheAI}\n`
      );
    }

    let finalResponseFromTheAI;

    if (this.shouldAnalyzeRecordsWithAI) {
      for (const record of formattedDataset) {
        await this.processRecord(record);
      }
      console.log(`Final prompt to the AI: ${finalAIPrompt}\n`);
      finalResponseFromTheAI = await this.generativeAI.chatWithAI(
        finalAIPrompt
      );
      console.log(`Final response from the AI: ${finalResponseFromTheAI}\n`);
    } else {
      const promises = [];
      formattedDataset.forEach((record) =>
        promises.push(this.processRecord(record))
      );
      await Promise.all(promises);
    }

    const operationStats = `
    Total files downloaded: ${this.downloadedRecords.length}
    Total number of functions downloaded: ${this.getTotalNumberOfFunctionsDownloaded()}
    Total number of functions downloaded, which are on file-level (excluding nested functions): ${this.getNumberOfFileLevelFunctions()}
    Total number of functions downloaded which are marked vulnerable: ${this.getNumberOfVulnerableFunctions()}
    Total number of functions downloaded which are marked vulnerable and has no vulnerable child function: ${this.getNumberOfInnerMostVulnerableFunctions()}

    There is an additional txt file for every downloaded file containing information in json format.
    ${
      this.shouldAnalyzeRecordsWithAI && finalResponseFromTheAI
        ? `\n${finalResponseFromTheAI}`
        : ""
    }
    `;

    console.log(operationStats);
    writeFile(this.statsFilePath, operationStats);
    writeFile(
      this.downloadedRecordsFilePath,
      JSON.stringify(this.downloadedRecords, null, 2)
    );
    if (this.shouldAnalyzeRecordsWithAI) {
      writeFile(
        this.aiChatHistoryPath,
        await this.generativeAI.getReadableHistory()
      );
    }

    this.downloadedRecords = [];
  }

  getTotalNumberOfFunctionsDownloaded = () => {
    return this.downloadedRecords.map((r) => r.functionsInVul).flat().length;
  };

  getNumberOfVulnerableFunctions = () => {
    return this.downloadedRecords
      .map((r) => r.functionsInVul)
      .flat()
      .filter((r) => r.isVuln).length;
  };

  getNumberOfFileLevelFunctions = () => {
    return this.downloadedRecords
      .map((r) => r.functionsInHierarchicalStructure)
      .flat().length;
  };

  getNumberOfInnerMostVulnerableFunctions = () => {
    return this.downloadedRecords
      .map((r) => r.innerMostVulnerableFunctions)
      .flat().length;
  };

  async processRecord(record) {
    const fullVulPath = `${this.currentDir}/datasets/javascriptDataset/${record.vulPath}`;
    const fullFixPath = `${this.currentDir}/datasets/combinedDataset/${record.fixPath}`;

    makeDir(fullVulPath);
    makeDir(fullFixPath);

    let isSuccessful = true;

    return fetchFile(record.fetchLink)
      .then((sourceCode) => {
        if (this.shouldAnalyzeRecordsWithAI) {
          const prompts = record.functionsInVul.map((func) =>
            removeTabsAndNewLines(
              getLinesFromString(sourceCode, func.startLine, func.endLine)
            )
          );
          return this.generativeAI.getSeriesOfResponses(
            { sourceCode },
            prompts
          );
        } else {
          return { sourceCode };
        }
      })
      .then((results) => {
        if (this.shouldAnalyzeRecordsWithAI && results.aiResponses) {
          record.aiResponses = results.aiResponses;
        }
        writeFileAsync(`${fullVulPath}/${record.fileName}`, results.sourceCode);
        writeFileAsync(
          `${fullFixPath}/${record.fileName}`,
          removeLinesFromString(
            results.sourceCode,
            record.functionsInHierarchicalStructure.filter((f) => f.isVuln)
          )
        );
        writeFileAsync(
          `${fullVulPath}/record.txt`,
          JSON.stringify(record, null, 2)
        );
      })
      .catch((err) => {
        isSuccessful = false;
        log(
          `ERROR, while fetching file from the url: ${record.fetchLink} - error trace: ${err}`
        );
      })
      .finally(() => {
        record.vulPath = `${record.vulPath}/${record.fileName}`;
        record.fixPath = `${record.fixPath}/${record.fileName}`;
        this.downloadedRecords.push(record);
        console.log(
          `${isSuccessful ? "SUCCESS" : "FAILED"} - download ${
            record.fileName
          } from ${record.fetchLink}`
        );
      });
  }

  getFormattedDataset = (dataset) => {
    const getFullFilename = (repoPath) => {
      return dataset.find((r) => r["full_repo_path"] === repoPath)?.path;
    };

    const getFilename = (repoPath) => {
      const splittedFileName = getFullFilename(repoPath)?.split("/");
      if (splittedFileName)
        return splittedFileName[splittedFileName.length - 1];
      else return;
    };

    const getOwnerAndProject = (repoPath) => {
      const splittedRepoPath = repoPath.split("/");
      return `${splittedRepoPath[3]}/${splittedRepoPath[4]}`;
    };

    const getCommitId = (repoPath) => {
      return repoPath.split("/")[6];
    };

    const getFetchableFileLink = (repoPath) => {
      return `https://api.github.com/repos/${getOwnerAndProject(
        repoPath
      )}/contents/${getFullFilename(repoPath)}?ref=${getCommitId(repoPath)}`;
    };

    const getPath = (repoPath, index, isFixFilePath) => {
      return `${isFixFilePath ? "clean/" : ""}${getOwnerAndProject(
        repoPath
      )}/${index}/${getCommitId(repoPath)}`;
    };

    const formattedDataset = [
      ...new Set(dataset.map((record) => record["full_repo_path"])),
    ];

    return formattedDataset.map((repoPath, index) => {
      const functionsInVul = dataset
        .filter((record) => record["full_repo_path"] === repoPath)
        .sort((a, b) => parseInt(a.line) - parseInt(b.line))
        .map((record, index) => ({
          name: `function${index}`,
          startLine: parseInt(record.line),
          endLine: parseInt(record.endline),
          isVuln: record.Vuln === "1" ? true : false,
        }));

      const functionsInHierarchicalStructure =
        getFunctionsInHierarchicalStructure(
          functionsInVul.map((f) => ({ ...f }))
        );

      const innerMostVulnerableFunctions = getInnerMostVulnerableFunctions(
        functionsInHierarchicalStructure
      );

      return {
        repoPath,
        fetchLink: getFetchableFileLink(repoPath),
        vulPath: getPath(repoPath, index, false),
        fixPath: getPath(repoPath, index, true),
        fullFileName: getFullFilename(repoPath),
        fileName: getFilename(repoPath),
        innerMostVulnerableFunctions,
        functionsInHierarchicalStructure,
        functionsInVul,
      };
    });
  };
}
