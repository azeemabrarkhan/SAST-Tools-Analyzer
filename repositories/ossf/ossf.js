import {
  writeFile,
  makeDir,
  readJsonFileSync,
  writeFileAsync,
} from "../../services/file.js";
import { fetchFile } from "../../services/http.js";
import { createNewLogFile, log } from "../../services/logger.js";
import AbstractSyntaxTree from "abstract-syntax-tree";

export default class Ossf {
  vulnerablityCount;
  currentDir;
  metaData;
  metaDataFilePath;

  constructor() {
    createNewLogFile();
    this.vulnerablityCount = 0;
    this.currentDir = process.cwd();
    this.metaData = [];
    this.metaDataFilePath = `${this.currentDir}\\repositories\\ossf\\metaData.json`;
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

  createMetaObj = (commit, ownerAndProject, sourceCode) => {
    const tree = new AbstractSyntaxTree(sourceCode);

    const functionDeclarations = tree
      .find("FunctionDeclaration")
      .map((node) => ({
        type: "FunctionDeclaration",
        startLine: node?.loc?.start?.line,
        endLine: node?.loc?.end?.line,
      }));
    const functionExpressions = tree.find("FunctionExpression").map((node) => ({
      type: "FunctionExpression",
      startLine: node?.loc?.start?.line,
      endLine: node?.loc?.end?.line,
    }));
    const arrowFunctionExpressions = tree
      .find("ArrowFunctionExpression")
      .map((node) => ({
        type: "ArrowFunctionExpression",
        startLine: node?.loc?.start?.line,
        endLine: node?.loc?.end?.line,
      }));

    const functionsInVul = [
      ...functionDeclarations,
      ...functionExpressions,
      ...arrowFunctionExpressions,
    ]
      .sort((a, b) => a.startLine - b.startLine)
      .map((f, index) => ({ name: `function${index}`, ...f }));

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
      functionsInVul,
    };

    for (let i = 0; i < prePatch.weaknesses.length; i++) {
      const splitFileName = prePatch.weaknesses[i].location.file.split("/");

      metaInfo.vulPath = `/vul/${CVE}/${ownerAndProject}/${
        this.vulnerablityCount
      }/${prePatch.commit}/${splitFileName[splitFileName.length - 1]}`;

      metaInfo.fixPath = `/fix/${CVE}/${ownerAndProject}/${
        this.vulnerablityCount
      }/${commit.postPatch.commit}/${splitFileName[splitFileName.length - 1]}`;

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

    const splitFileName = fileName.split("/");

    return fetchFile(vulFileUrl)
      .then((text) => {
        writeFileAsync(
          `${vulPath}\\${splitFileName[splitFileName.length - 1]}`,
          text
        );
        writeFileAsync(
          `${vulPath}\\weaknesses.txt`,
          JSON.stringify(prePatch.weaknesses, null, 2)
        );
        return text;
      })
      .catch((err) =>
        log(
          `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
        )
      )
      .then((sourceCode) => {
        try {
          this.createMetaObj(commit, ownerAndProject, sourceCode);
        } catch (err) {
          log(
            `ERROR, while splitting source file into functions - ${commit.repository} - error trace: ${err}`
          );
        }
      })
      .then(() =>
        fetchFile(fixFileUrl)
          .then((text) => {
            writeFileAsync(
              `${fixPath}\\${splitFileName[splitFileName.length - 1]}`,
              text
            );
            writeFileAsync(
              `${fixPath}\\weaknesses.txt`,
              JSON.stringify(prePatch.weaknesses, null, 2)
            );
          })
          .catch((err) =>
            log(
              `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
            )
          )
      );
  };
}
