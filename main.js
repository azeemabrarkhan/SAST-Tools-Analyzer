import { fetchCommit, fetchFile } from "./services/http.js";
import { makeDir, writeFileAsync, csvToArray } from "./services/file.js";
import { log, clearLog } from "./services/logger.js";

const currentDir = process.cwd();
const prePatchDir = `${currentDir}\\dataset\\pre-patch\\`;
const postPatchDir = `${currentDir}\\dataset\\post-patch\\`;
const secbenchFilePath = `${currentDir}\\commitIDs\\secbench.csv`;

let fileNumber = 1;

const processCommit = async (commitUrl, isVul) => {
  return new Promise(async (resolve, reject) => {
    try {
      const response = await fetchCommit(commitUrl);
      const commitData = await response.json();

      if (commitData.files && commitData.files.length > 0) {
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
              `${isVul ? prePatchDir : postPatchDir}${
                splitFileName[splitFileName.length - 1]
              }`,
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

const main = async () => {
  makeDir(prePatchDir);
  makeDir(postPatchDir);
  const secbenchData = await csvToArray(secbenchFilePath);

  for (const secbenchCommit of secbenchData) {
    await processCommit(
      `https://api.github.com/repos/${secbenchCommit.owner}/${secbenchCommit.project}/commits/${secbenchCommit["sha-p"]}`,
      true
    );
    await processCommit(
      `https://api.github.com/repos/${secbenchCommit.owner}/${secbenchCommit.project}/commits/${secbenchCommit.sha}`,
      false
    );
  }
};

clearLog();
main();
