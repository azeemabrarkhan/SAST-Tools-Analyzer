import {
  writeFile,
  makeDir,
  readJsonFileSync,
  writeFileAsync,
  deleteFile,
} from "../../services/file.js";
import { fetchFile } from "../../services/http.js";
import { createNewLogFile, log } from "../../services/logger.js";
import AbstractSynTree from "../../services/abstractSynTree.js";

export default class Ossf {
  vulnerablityCount;
  currentDir;
  metaData;
  metaDataFilePath;
  abstractSyntaxTree;

  constructor() {
    createNewLogFile();
    this.vulnerablityCount = 0;
    this.currentDir = process.cwd();
    this.metaData = [];
    this.metaDataFilePath = `${this.currentDir}\\repositories\\ossf\\metaData.json`;
    this.abstractSyntaxTree = new AbstractSynTree();
  }

  scrape = async () => {
    const data = readJsonFileSync(
      `${this.currentDir}\\repositories\\ossf\\ossf.json`
    );

    for (const commit of data) {
      this.vulnerablityCount++;
      await this.processCommit(commit);
    }

    console.log("length = ", this.metaData.length);
    writeFile(this.metaDataFilePath, JSON.stringify(this.metaData, null, 4));
    this.vulnerablityCount = 0;
  };

  getFileNameWithExt = (location) => {
    const splitFileName = location.file.split("/");
    return `${splitFileName[splitFileName.length - 1]}${
      location.implicitExtension ? `.${location.implicitExtension}` : ""
    }`;
  };

  createMetaObj = (commit, ownerAndProject, sourceCode) => {
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
      functionsInVul: this.abstractSyntaxTree.getFunctionsLocation(sourceCode),
    };

    for (let i = 0; i < prePatch.weaknesses.length; i++) {
      const fileNameWithExt = this.getFileNameWithExt(
        prePatch.weaknesses[i].location
      );

      metaInfo.vulPath = `/vul/${CVE}/${ownerAndProject}/${this.vulnerablityCount}/${prePatch.commit}/${fileNameWithExt}`;

      metaInfo.fixPath = `/fix/${CVE}/${ownerAndProject}/${this.vulnerablityCount}/${commit.postPatch.commit}/${fileNameWithExt}`;

      metaInfo.lineNumber = prePatch.weaknesses[i].location.line;
      metaInfo.explanation = prePatch.weaknesses[i].explanation;

      this.metaData.push(metaInfo);
    }
  };

  processCommit = async (commit) => {
    const { CVE, repository, prePatch, postPatch } = commit;

    const splittedUrl = repository.split("/");
    const ownerAndProject = `${splittedUrl[3]}/${splittedUrl[4].split(".")[0]}`;

    const vulPath = `${
      this.currentDir
    }\\datasets\\ossf\\vul\\${CVE}\\${ownerAndProject.replace("/", "\\")}\\${
      this.vulnerablityCount
    }\\${prePatch.commit}`;

    const fixPath = `${
      this.currentDir
    }\\datasets\\ossf\\fix\\${CVE}\\${ownerAndProject.replace("/", "\\")}\\${
      this.vulnerablityCount
    }\\${postPatch.commit}`;

    makeDir(vulPath);
    makeDir(fixPath);

    const fileName = prePatch.weaknesses[0].location.file;
    console.log(`${this.vulnerablityCount} - ${fileName}`);

    const baseUrl = `https://api.github.com/repos/${ownerAndProject}`;
    const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${prePatch.commit}`;
    const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${postPatch.commit}`;

    const fileNameWithExt = this.getFileNameWithExt(
      prePatch.weaknesses[0].location
    );

    return fetchFile(vulFileUrl)
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
          this.createMetaObj(commit, ownerAndProject, sourceCode);
        } catch (err) {
          log(
            `ERROR, while splitting source file into functions ${vulPath}\\${fileNameWithExt} - error trace: ${err}`
          );
        }
      })
      .then(() =>
        fetchFile(fixFileUrl)
          .then((sourceCode) => {
            writeFileAsync(`${fixPath}\\${fileNameWithExt}`, sourceCode);
            writeFileAsync(
              `${fixPath}\\weaknesses.txt`,
              JSON.stringify(prePatch.weaknesses, null, 2)
            );
          })
          .catch((err) => {
            log(
              `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
            );
            deleteFile(`${vulPath}\\${fileNameWithExt}`);
          })
      )
      .catch((err) =>
        log(
          `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
        )
      );
  };
}
