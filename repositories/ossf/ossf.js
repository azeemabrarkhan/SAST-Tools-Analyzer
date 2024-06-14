import {
  writeFile,
  makeDir,
  readJsonFileSync,
  writeFileAsync,
  deleteFile,
} from "../../services/file.js";
import { fetchFile } from "../../services/http.js";
import { log } from "../../services/logger.js";
import AbstractSynTree from "../../services/abstractSynTree.js";
import { getSingleLineFromString } from "../../utils/text.js";

export default class Ossf {
  currentDir;
  downloadedRecords;
  downloadedRecordsFilePath;
  statsFilePath;
  abstractSyntaxTree;
  numberOfFilesDownloaded;

  constructor() {
    this.currentDir = process.cwd();
    this.downloadedRecords = [];
    this.datasetFilePath = `${this.currentDir}/repositories/ossf/records.json`;
    this.downloadedRecordsFilePath = `${this.currentDir}/repositories/ossf/downloadedRecords.json`;
    this.statsFilePath = `${this.currentDir}/datasets/ossf/stats.txt`;
    this.abstractSyntaxTree = new AbstractSynTree();
    this.numberOfFilesDownloaded = 0;
  }

  scrape = async () => {
    const data = readJsonFileSync(this.datasetFilePath);

    const promises = [];

    data.forEach((commit, index) => {
      promises.push(this.processCommit(commit, index));
    });

    await Promise.all(promises);

    const operationStats = `
    Total number of vulnerablities in records: ${this.downloadedRecords.length}
    Total vulnerable files downloaded: ${this.numberOfFilesDownloaded}
    Total fix files downloaded: ${this.numberOfFilesDownloaded}
    Total files downloaded: ${this.numberOfFilesDownloaded * 2}

    There is an additional txt file for every vulnerable and fix file containing meta data regarding vulnerablities.
    `;

    console.log(operationStats);
    writeFile(this.statsFilePath, operationStats);
    writeFile(
      this.downloadedRecordsFilePath,
      JSON.stringify(this.downloadedRecords, null, 4)
    );
    this.numberOfFilesDownloaded = 0;
  };

  getFileNameWithExt = (location) => {
    const splitFileName = location.file.split("/");
    return `${splitFileName[splitFileName.length - 1]}${
      location.implicitExtension ? `.${location.implicitExtension}` : ""
    }`;
  };

  createdownloadedRecordObj = (
    commit,
    ownerAndProject,
    vulFileSourceCode,
    fixFileSourceCode,
    index
  ) => {
    const { CVE, CWEs, repository: repoPath, prePatch, postPatch } = commit;

    const record = {
      CVE,
      CWEs,
      repoPath,
      prePatch: prePatch.commit,
      postPatch: postPatch.commit,
      vulPath: "",
      fixPath: "",
      lineNumber: 0,
      explanation: "",
      fullFileName: "",
      fileName: "",
      vulLine: "",
      functionsInVul:
        this.abstractSyntaxTree.getFunctionsLocations(vulFileSourceCode),
      functionsInFix:
        this.abstractSyntaxTree.getFunctionsLocations(fixFileSourceCode),
    };

    for (let i = 0; i < prePatch.weaknesses.length; i++) {
      const fileNameWithExt = this.getFileNameWithExt(
        prePatch.weaknesses[i].location
      );

      record.vulPath = `vul/${CVE}/${ownerAndProject}/${index}/${prePatch.commit}/${fileNameWithExt}`;

      record.fixPath = `fix/${CVE}/${ownerAndProject}/${index}/${commit.postPatch.commit}/${fileNameWithExt}`;

      record.lineNumber = prePatch.weaknesses[i].location.line;
      record.explanation = prePatch.weaknesses[i].explanation;
      record.fullFileName = prePatch.weaknesses[i].location.file;
      record.fileName = fileNameWithExt;

      record.vulLine = getSingleLineFromString(
        vulFileSourceCode,
        record.lineNumber
      );

      this.downloadedRecords.push({ ...record });
    }
  };

  processCommit = async (commit, index) => {
    const { CVE, repository, prePatch, postPatch } = commit;

    const splittedUrl = repository.split("/");
    const ownerAndProject = `${splittedUrl[3]}/${splittedUrl[4].split(".")[0]}`;

    const vulPath = `${this.currentDir}/datasets/ossf/vul/${CVE}/${ownerAndProject}/${index}/${prePatch.commit}`;

    const fixPath = `${this.currentDir}/datasets/ossf/fix/${CVE}/${ownerAndProject}/${index}/${postPatch.commit}`;

    const vulPathForCombinedDataset = `${this.currentDir}/datasets/combinedDataset/vul/${CVE}/${ownerAndProject}/${index}/${prePatch.commit}`;

    makeDir(vulPath);
    makeDir(fixPath);
    makeDir(vulPathForCombinedDataset);

    const fileName = prePatch.weaknesses[0].location.file;

    const baseUrl = `https://api.github.com/repos/${ownerAndProject}`;
    const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${prePatch.commit}`;
    const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${postPatch.commit}`;

    const fileNameWithExt = this.getFileNameWithExt(
      prePatch.weaknesses[0].location
    );

    let isSuccessful = true;
    let fixFile = "";

    return fetchFile(fixFileUrl)
      .then((fixFileSourceCode) => {
        writeFileAsync(`${fixPath}/${fileNameWithExt}`, fixFileSourceCode);
        writeFileAsync(
          `${fixPath}/weaknesses.txt`,
          JSON.stringify(prePatch.weaknesses, null, 2)
        );
        fixFile = fixFileSourceCode;
      })
      .then(() =>
        fetchFile(vulFileUrl)
          .then((vulFileSourceCode) => {
            writeFileAsync(`${vulPath}/${fileNameWithExt}`, vulFileSourceCode);
            writeFileAsync(
              `${vulPathForCombinedDataset}/${fileNameWithExt}`,
              vulFileSourceCode
            );
            writeFileAsync(
              `${vulPath}/weaknesses.txt`,
              JSON.stringify(prePatch.weaknesses, null, 2)
            );
            return vulFileSourceCode;
          })
          .then((vulFileSourceCode) => {
            try {
              this.createdownloadedRecordObj(
                commit,
                ownerAndProject,
                vulFileSourceCode,
                fixFile,
                index
              );
              this.numberOfFilesDownloaded++;
            } catch (err) {
              isSuccessful = false;
              log(
                `ERROR, while splitting source file into functions ${vulPath}/${fileNameWithExt} - error trace: ${err}`
              );
              deleteFile(`${fixPath}/${fileNameWithExt}`);
              deleteFile(`${fixPath}/weaknesses.txt`);
              deleteFile(`${vulPath}/${fileNameWithExt}`);
              deleteFile(`${vulPath}/weaknesses.txt`);
              deleteFile(`${vulPathForCombinedDataset}/${fileNameWithExt}`);
            }
          })
          .catch((err) => {
            isSuccessful = false;
            log(
              `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
            );
            deleteFile(`${fixPath}/${fileNameWithExt}`);
            deleteFile(`${fixPath}/weaknesses.txt`);
          })
      )
      .catch((err) => {
        isSuccessful = false;
        log(
          `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
        );
      })
      .finally(() =>
        console.log(
          `${
            isSuccessful ? "SUCCESS" : "FAILED"
          } - download ${fileName} from ${repository}`
        )
      );
  };
}
