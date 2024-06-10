export const getLinesFromString = (str, from, to) => {
  if (str && from && to) {
    return str
      .split("\n")
      .slice(from - 1, to + 1)
      .join("\n");
  } else {
    return "";
  }
};

export const getSingleLineFromString = (str, lineNumber) => {
  return str ? str.split("\n")[lineNumber - 1]?.trim() : "";
};

export const removeLinesFromString = (str, blocksToRemove) => {
  if (!str) return "";

  const splittedString = str.split("\n");
  for (let block of blocksToRemove) {
    if (splittedString.length >= block.endLine) {
      for (let i = block.startLine - 1; i < block.endLine; i++) {
        splittedString[i] = null;
      }
    } else {
      return "";
    }
  }

  return splittedString.filter((line) => line).join("\n");
};

export const removeTabsAndNewLines = (str) => {
  return str
    .split("\n")
    .reduce((acc, value) => acc + value, "")
    .split("\t")
    .reduce((acc, value) => acc + value, "")
    .split(" ")
    .reduce((acc, value) => acc + value, "");
};
