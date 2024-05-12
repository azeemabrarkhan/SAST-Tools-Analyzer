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

export default class Ossf {
  currentDir;
  metaData;
  metaDataFilePath;
  statsFilePath;
  abstractSyntaxTree;
  numberOfFilesDownloaded;

  constructor() {
    this.currentDir = process.cwd();
    this.metaData = [];
    this.metaDataFilePath = `${this.currentDir}\\repositories\\ossf\\metaData.json`;
    this.statsFilePath = `${this.currentDir}\\datasets\\ossf\\stats.txt`;
    this.abstractSyntaxTree = new AbstractSynTree();
    this.numberOfFilesDownloaded = 0;
  }

  scrape = async () => {
    const data = readJsonFileSync(
      `${this.currentDir}\\repositories\\ossf\\ossf.json`
    );

    const promises = [];

    data.forEach((commit, index) => {
      promises.push(this.processCommit(commit, index));
    });

    await Promise.all(promises);

    const operationStats = `
    Total number of vulnerablities in records: ${this.metaData.length}
    Total vulnerable files downloaded: ${this.numberOfFilesDownloaded}
    Total fix files downloaded: ${this.numberOfFilesDownloaded}
    Total files downloaded: ${this.numberOfFilesDownloaded * 2}

    There is an additional txt file for every vulnerable and fix file containing meta data regarding vulnerablities.
    `;

    console.log(operationStats);
    writeFile(this.statsFilePath, operationStats);
    writeFile(this.metaDataFilePath, JSON.stringify(this.metaData, null, 4));
    this.numberOfFilesDownloaded = 0;
  };

  getFileNameWithExt = (location) => {
    const splitFileName = location.file.split("/");
    return `${splitFileName[splitFileName.length - 1]}${
      location.implicitExtension ? `.${location.implicitExtension}` : ""
    }`;
  };

  createMetaObj = (commit, ownerAndProject, sourceCode, index) => {
    const { CVE, CWEs, repository, prePatch, postPatch } = commit;

    const metaInfo = {
      CVE,
      CWEs,
      repository,
      prePatch: prePatch.commit,
      postPatch: postPatch.commit,
      vulPath: "",
      fixPath: "",
      lineNumber: 0,
      explanation: "",
      functionsInVul: this.abstractSyntaxTree.getFunctionsLocations(sourceCode),
    };

    for (let i = 0; i < prePatch.weaknesses.length; i++) {
      const fileNameWithExt = this.getFileNameWithExt(
        prePatch.weaknesses[i].location
      );

      metaInfo.vulPath = `vul/${CVE}/${ownerAndProject}/${index}/${prePatch.commit}/${fileNameWithExt}`;

      metaInfo.fixPath = `fix/${CVE}/${ownerAndProject}/${index}/${commit.postPatch.commit}/${fileNameWithExt}`;

      metaInfo.lineNumber = prePatch.weaknesses[i].location.line;
      metaInfo.explanation = prePatch.weaknesses[i].explanation;

      this.metaData.push(metaInfo);
    }
  };

  processCommit = async (commit, index) => {
    const { CVE, repository, prePatch, postPatch } = commit;

    const splittedUrl = repository.split("/");
    const ownerAndProject = `${splittedUrl[3]}/${splittedUrl[4].split(".")[0]}`;

    const vulPath = `${
      this.currentDir
    }\\datasets\\ossf\\vul\\${CVE}\\${ownerAndProject.replace(
      "/",
      "\\"
    )}\\${index}\\${prePatch.commit}`;

    const fixPath = `${
      this.currentDir
    }\\datasets\\ossf\\fix\\${CVE}\\${ownerAndProject.replace(
      "/",
      "\\"
    )}\\${index}\\${postPatch.commit}`;

    makeDir(vulPath);
    makeDir(fixPath);

    const fileName = prePatch.weaknesses[0].location.file;

    const baseUrl = `https://api.github.com/repos/${ownerAndProject}`;
    const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${prePatch.commit}`;
    const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${postPatch.commit}`;

    const fileNameWithExt = this.getFileNameWithExt(
      prePatch.weaknesses[0].location
    );

    let isSuccessful = true;

    return fetchFile(fixFileUrl)
      .then((sourceCode) => {
        writeFileAsync(`${fixPath}\\${fileNameWithExt}`, sourceCode);
        writeFileAsync(
          `${fixPath}\\weaknesses.txt`,
          JSON.stringify(prePatch.weaknesses, null, 2)
        );
      })
      .then(() =>
        fetchFile(vulFileUrl)
          .then((sourceCode) => {
            writeFileAsync(`${vulPath}\\${fileNameWithExt}`, sourceCode);
            writeFileAsync(
              `${vulPath}\\weaknesses.txt`,
              JSON.stringify(prePatch.weaknesses, null, 2)
            );
            return sourceCode;
          })
          .then((sourceCode) => {
            try {
              this.createMetaObj(commit, ownerAndProject, sourceCode, index);
              this.numberOfFilesDownloaded++;
            } catch (err) {
              isSuccessful = false;
              log(
                `ERROR, while splitting source file into functions ${vulPath}\\${fileNameWithExt} - error trace: ${err}`
              );
              deleteFile(`${fixPath}\\${fileNameWithExt}`);
              deleteFile(`${fixPath}\\weaknesses.txt`);
              deleteFile(`${vulPath}\\${fileNameWithExt}`);
              deleteFile(`${vulPath}\\weaknesses.txt`);
            }
          })
          .catch((err) => {
            isSuccessful = false;
            log(
              `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
            );
            deleteFile(`${fixPath}\\${fileNameWithExt}`);
            deleteFile(`${fixPath}\\weaknesses.txt`);
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
