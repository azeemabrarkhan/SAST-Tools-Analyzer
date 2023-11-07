import dotenv from "dotenv";

dotenv.config();

const headers = new Headers();
headers.append("Authorization", process.env.AUTH_TOKEN);

const options = {
  method: "GET",
  headers: headers,
};

export const fetchCommit = (commitUrl) => {
  return fetch(commitUrl, options);
};

export const fetchFile = async (fileUrl) => {
  return fetch(fileUrl, options)
    .then((fileResponse) => fileResponse.json())
    .then((fileMetaData) => fetchCommit(fileMetaData["download_url"]))
    .then((file) => file.text());
};
