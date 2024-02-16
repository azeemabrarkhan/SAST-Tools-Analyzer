import { readJsonFileSync } from "./services/file.js";

export function printRecursiveObject(obj, indent = 0) {
  const spaces = " ".repeat(indent * 2);

  for (const key in obj) {
    if (typeof obj[key] === "object" && obj[key] !== null) {
      console.log(`${spaces}${key}: {`);
      printRecursiveObject(obj[key], indent + 1);
      console.log(`${spaces}},`);
    } else {
      console.log(`${spaces}${key}: "${obj[key]}",`);
    }
  }
}

// print CWEs
const meta = readJsonFileSync(
  `${process.cwd()}\\repositories\\ossf\\metaData.json`
);
console.log(new Set(meta.map((m) => m.CWEs).reduce((a, b) => [...a, ...b])));
