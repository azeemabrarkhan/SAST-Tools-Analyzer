import { fetchCommit, fetchFile } from "./services/http.js";
import { makeDir, writeFileAsync, csvToArray } from "./services/file.js";
import { log, clearLog } from "./services/logger.js";
import readline from "readline";

const currentDir = process.cwd();
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});
const secbenchFilePath = `${currentDir}\\commitIDs\\secbench.csv`;

let fileNumber = 1;

const processCommit = async (secbenchCommit, isVul) => {
  const commitUrl = `https://api.github.com/repos/${secbenchCommit.owner}/${
    secbenchCommit.project
  }/commits/${isVul ? secbenchCommit["sha-p"] : secbenchCommit.sha}`;

  return new Promise(async (resolve, reject) => {
    try {
      const response = await fetchCommit(commitUrl);
      const commitData = await response.json();

      if (commitData.files && commitData.files.length > 0) {
        const pathToSaveFiles = `${currentDir}\\datasets\\secbench\\${
          secbenchCommit.language
        }\\${secbenchCommit["cwe_id"]}\\${secbenchCommit.project}\\${
          isVul
            ? `pre-patch-${commitData.sha}\\`
            : `post-patch-${commitData.sha}\\`
        }`;

        makeDir(pathToSaveFiles);

        const files = commitData.files.map((file) => ({
          fileName: file.filename,
          url: file.raw_url,
        }));

        for (const file of files) {
          console.log(fileNumber);
          fileNumber++;
          try {
            const rawFileObj = await fetchFile(file.url);
            const rawFileText = await rawFileObj.text();
            const splitFileName = file.fileName.split("/");
            writeFileAsync(
              `${pathToSaveFiles}${splitFileName[splitFileName.length - 1]}`,
              rawFileText
            );
            resolve();
          } catch (err) {
            log(
              `ERROR, while fetching file '${file.fileName}' from the url: ${file.url} - error trace: ${err}`
            );
            reject(err);
          }
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
        `ERROR, while fetching commit from the url: ${commitUrl} - error trace: ${err}`
      );
      reject(err);
    }
  });
};

const printMenu = async () => {
  return new Promise((resolve) => {
    rl.question(
      `Choose from the following option.
    1- Fetch Secbench Commits
    2- End Program

    `,
      (option) => resolve(parseInt(option))
    );
  });
};

const main = async () => {
  let shouldContinue = true;

  while (shouldContinue) {
    const option = await printMenu();
    switch (option) {
      case 1:
        const secbenchData = await csvToArray(secbenchFilePath);
        for (const secbenchCommit of secbenchData) {
          await processCommit(secbenchCommit, true);
          await processCommit(secbenchCommit, false);
        }
        break;
      case 2:
        shouldContinue = false;
        rl.close();
        break;
    }
  }
};

clearLog();
main();
