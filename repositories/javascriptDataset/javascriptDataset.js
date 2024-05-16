import {
  csvToArray,
  writeFileAsync,
  makeDir,
  writeFile,
} from "../../services/file.js";
import { fetchFile } from "../../services/http.js";
import { log } from "../../services/logger.js";
import { getFunctionsInHierarchicalStructure } from "../../utils/functions.js";

export default class JavascriptDataset {
  currentDir;
  datasetFilePath;
  metaDataFilePath;
  statsFilePath;
  downloadedRecords;

  constructor() {
    this.currentDir = process.cwd();
    this.datasetFilePath = `repositories\\javascriptDataset\\dataset.csv`;
    this.metaDataFilePath = `${this.currentDir}\\repositories\\javascriptDataset\\metaData.json`;
    this.statsFilePath = `${this.currentDir}\\datasets\\javascriptDataset\\stats.txt`;
    this.downloadedRecords = [];
  }

  async scrape() {
    const dataset = await csvToArray(this.datasetFilePath);
    const formattedDataset = this.getFormattedDataset(dataset);

    const promises = [];

    formattedDataset.forEach((record) => {
      promises.push(this.processRecord(record));
    });

    await Promise.all(promises);

    const totalFunctionsCount = this.getTotalNumberOfFunctionsDownloaded();
    const vulnerableFunctionsCount = this.getNumberOfVulnerableFunctions();

    const operationStats = `
    Total files downloaded: ${this.downloadedRecords.length}
    Total number of functions: ${totalFunctionsCount}
    Total number of vulnerable functions: ${vulnerableFunctionsCount}
    Total number of clean functions: ${
      totalFunctionsCount - vulnerableFunctionsCount
    }

    There is an additional txt file for every downloaded file containing information in json format.
    `;

    console.log(operationStats);
    writeFile(this.statsFilePath, operationStats);
    writeFile(
      this.metaDataFilePath,
      JSON.stringify(this.downloadedRecords, null, 2)
    );
    this.downloadedRecords = [];
  }

  getTotalNumberOfFunctionsDownloaded = () => {
    return this.downloadedRecords.map((r) => r.functions).flat().length;
  };

  getNumberOfVulnerableFunctions = () => {
    return this.downloadedRecords
      .map((r) => r.functions)
      .flat()
      .filter((r) => r.isVuln).length;
  };

  async processRecord(record) {
    makeDir(record.dirPath);
    let isSuccessful = true;

    return fetchFile(record.fetchLink)
      .then((sourceCode) => {
        writeFileAsync(`${record.dirPath}\\${record.fileName}`, sourceCode);
        writeFileAsync(
          `${record.dirPath}\\record.txt`,
          JSON.stringify(record, null, 2)
        );
        this.downloadedRecords.push(record);
      })
      .catch((err) => {
        isSuccessful = false;
        log(
          `ERROR, while fetching file from the url: ${record.fetchLink} - error trace: ${err}`
        );
      })
      .finally(() =>
        console.log(
          `${isSuccessful ? "SUCCESS" : "FAILED"} - download ${
            record.fileName
          } from ${record.fetchLink}`
        )
      );
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

    const getDirPath = (repoPath, index) => {
      return `${
        this.currentDir
      }\\datasets\\javascriptDataset\\${getOwnerAndProject(repoPath).replace(
        "/",
        "\\"
      )}\\${index}\\${getCommitId(repoPath)}`;
    };

    const formattedDataset = [
      ...new Set(dataset.map((record) => record["full_repo_path"])),
    ];

    return formattedDataset.map((repoPath, index) => {
      const functions = dataset
        .filter((record) => record["full_repo_path"] === repoPath)
        .sort((a, b) => parseInt(a.line) - parseInt(b.line))
        .map((record, index) => ({
          name: `function${index}`,
          startLine: parseInt(record.line),
          endLine: parseInt(record.endline),
          isVuln: record.Vuln === "1" ? true : false,
        }));

      return {
        repoPath,
        fetchLink: getFetchableFileLink(repoPath),
        dirPath: getDirPath(repoPath, index),
        fullFileName: getFullFilename(repoPath),
        fileName: getFilename(repoPath),
        functions,
        functionsInHierarchicalStructure: getFunctionsInHierarchicalStructure(
          functions.map((f) => ({ ...f }))
        ),
      };
    });
  };
}
