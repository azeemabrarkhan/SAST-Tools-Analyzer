import { csvToArray, makeDir, writeFileAsync } from "../../services/file.js";
import { fetchCommit, fetchFile } from "../../services/http.js";
import { log } from "../../services/logger.js";

export default class Secbench {
  vulnerablityCount;
  currentDir;

  constructor() {
    this.vulnerablityCount = 0;
    this.currentDir = process.cwd();
  }

  scrape = async (partNumber) => {
    const data = await csvToArray(
      `${this.currentDir}/repositories/secbench/secbench${partNumber}.csv`
    );
    for (const commit of data) {
      this.vulnerablityCount++;

      const baseUrl = `https://api.github.com/repos/${commit.owner}/${commit.project}`;

      const vulPath = `${this.currentDir}/datasets/secbench/vul/${commit.language}/${commit["cwe_id"]}/${commit.owner}/${commit.project}/${this.vulnerablityCount}/${commit["sha-p"]}`;
      const fixPath = `${this.currentDir}/datasets/secbench/fix/${commit.language}/${commit["cwe_id"]}/${commit.owner}/${commit.project}/${this.vulnerablityCount}/${commit.sha}`;

      await this.processSecbenchCommit(
        baseUrl,
        vulPath,
        fixPath,
        commit["sha-p"],
        commit.sha
      );
    }
    this.vulnerablityCount = 0;
  };

  processSecbenchCommit = async (baseUrl, vulPath, fixPath, shaV, sha) => {
    const commitUrl = `${baseUrl}/commits/${sha}`;
    makeDir(vulPath);
    makeDir(fixPath);

    return new Promise(async (resolve) => {
      try {
        const commitResponse = await fetchCommit(commitUrl);
        const commitData = await commitResponse.json();

        if (commitData.files && commitData.files.length > 0) {
          const fileNames = commitData.files
            .filter((file) => file.status !== "added")
            .map((file) => file.filename);

          for (const fileName of fileNames) {
            console.log(`${this.vulnerablityCount} - ${fileName}`);
            const splitFileName = fileName.split("/");
            const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${shaV}`;
            const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${sha}`;

            fetchFile(vulFileUrl)
              .then((text) =>
                writeFileAsync(
                  `${vulPath}/${splitFileName[splitFileName.length - 1]}`,
                  text
                )
              )
              .catch((err) => {
                log(
                  `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
                );
                resolve();
              });

            fetchFile(fixFileUrl)
              .then((text) => {
                writeFileAsync(
                  `${fixPath}/${splitFileName[splitFileName.length - 1]}`,
                  text
                );
                if (fileNames.indexOf(fileName) === fileNames.length - 1) {
                  resolve();
                }
              })
              .catch((err) => {
                log(
                  `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
                );
                resolve();
              });
          }
        } else if (commitData.files && commitData.files.length === 0) {
          log(
            `WARNING, files array does not contain any file for url: ${commitUrl} - message: ${commitData.message}`
          );
          resolve();
        } else {
          log(
            `WARNING, files array does not exist for url: ${commitUrl} - message: ${commitData.message}`
          );
          resolve();
        }
      } catch (err) {
        log(
          `ERROR, while fetching commit from the url: ${commitUrl} - message: ${commitData.message} - error trace: ${err}`
        );
        resolve();
      }
    });
  };
}
