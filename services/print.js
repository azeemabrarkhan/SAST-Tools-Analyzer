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
