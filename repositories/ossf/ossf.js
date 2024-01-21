import {
  writeFile,
  appendFile,
  makeDir,
  readJsonFileSync,
  writeFileAsync,
} from "../../services/file.js";
import { fetchFile } from "../../services/http.js";
import { createNewLogFile, log } from "../../services/logger.js";

export default class Ossf {
  vulnerablityCount;
  currentDir;
  metaDataFilePath;

  constructor() {
    createNewLogFile();
    this.vulnerablityCount = 0;
    this.currentDir = process.cwd();
    this.metaDataFilePath = `${this.currentDir}\\repositories\\ossf\\metaData.csv`;
    writeFile(
      this.metaDataFilePath,
      `CVE, CWEs, repository, prePatch, postPatch, vulPath, fixPath, lineNumber, explanation`
    );
  }

  scrape = async () => {
    const data = readJsonFileSync(
      `${this.currentDir}\\repositories\\ossf\\ossf.json`
    );
    for (const commit of data) {
      this.vulnerablityCount++;

      const splittedUrl = commit.repository.split("/");
      const ownerAndProject = `${splittedUrl[3]}/${
        splittedUrl[4].split(".")[0]
      }`;
      const baseUrl = `https://api.github.com/repos/${ownerAndProject}`;

      const vulPath = `${this.currentDir}\\datasets\\ossf\\vul\\${
        commit.CVE
      }\\${ownerAndProject.replace("/", "\\")}\\${this.vulnerablityCount}\\${
        commit.prePatch.commit
      }`;
      const fixPath = `${this.currentDir}\\datasets\\ossf\\fix\\${
        commit.CVE
      }\\${ownerAndProject.replace("/", "\\")}\\${this.vulnerablityCount}\\${
        commit.postPatch.commit
      }`;

      this.recordMetaData(commit, ownerAndProject);

      await this.processCommit(
        baseUrl,
        vulPath,
        fixPath,
        commit.prePatch.commit,
        commit.postPatch.commit,
        commit.prePatch.weaknesses[0].location.file,
        JSON.stringify(commit.prePatch.weaknesses, null, 2)
      );
    }
    this.vulnerablityCount = 0;
  };

  recordMetaData = (commit, ownerAndProject) => {
    const { CVE, CWEs, repository, prePatch, postPatch } = commit;

    const vulPath = `/vul/${CVE}/${ownerAndProject}/${this.vulnerablityCount}/${prePatch.commit}`;
    const fixPath = `/fix/${CVE}/${ownerAndProject}/${this.vulnerablityCount}/${commit.postPatch.commit}`;

    for (let i = 0; i < prePatch.weaknesses.length; i++) {
      const splitFileName = prePatch.weaknesses[i].location.file.split("/");
      appendFile(
        this.metaDataFilePath,
        `\n${CVE}, ${String(CWEs).replaceAll(",", "-")}, ${repository}, ${
          prePatch.commit
        }, ${postPatch.commit}, ${vulPath}/${
          splitFileName[splitFileName.length - 1]
        }, ${fixPath}/${splitFileName[splitFileName.length - 1]}, ${
          prePatch.weaknesses[i].location.line
        }, ${prePatch.weaknesses[i].explanation}`
      );
    }
  };

  processCommit = async (
    baseUrl,
    vulPath,
    fixPath,
    shaV,
    sha,
    fileName,
    weaknessesString
  ) => {
    makeDir(vulPath);
    makeDir(fixPath);

    console.log(`${this.vulnerablityCount} - ${fileName}`);
    const splitFileName = fileName.split("/");
    const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${shaV}`;
    const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${sha}`;

    return fetchFile(vulFileUrl)
      .then((text) => {
        writeFileAsync(
          `${vulPath}\\${splitFileName[splitFileName.length - 1]}`,
          text
        );
        writeFileAsync(`${vulPath}\\weaknesses.txt`, weaknessesString);
      })
      .catch((err) =>
        log(
          `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
        )
      )
      .then(() =>
        fetchFile(fixFileUrl)
          .then((text) => {
            writeFileAsync(
              `${fixPath}\\${splitFileName[splitFileName.length - 1]}`,
              text
            );
            writeFileAsync(`${fixPath}\\weaknesses.txt`, weaknessesString);
          })
          .catch((err) =>
            log(
              `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
            )
          )
      );
  };
}
