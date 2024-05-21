export const getLinesFromString = (str, from, to) => {
  return str
    ? str
        .split("\n")
        .slice(from - 1, to + 1)
        .join("\n")
    : "";
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
