export const getLinesFromString = (str, from, to) => {
  return str
    ? str
        .split("\n")
        .slice(from - 1, to + 1)
        .join("\n")
    : "";
};
