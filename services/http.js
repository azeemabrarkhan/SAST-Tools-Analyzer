import dotenv from "dotenv";

dotenv.config();
const headers = new Headers();
headers.append("Authorization", process.env.AUTH_TOKEN);

export const fetchCommit = (commitUrl) => {
  return fetch(commitUrl, {
    method: "GET",
    headers: headers,
  });
};

export const fetchFile = (rawFileUrl) => {
  try {
    return fetch(rawFileUrl, {
      method: "GET",
      headers: headers,
    });
  } catch {}
};
