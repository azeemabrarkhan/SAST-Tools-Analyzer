export const getFunctionsInHierarchicalStructure = (functions) => {
  function getChildrenFunctionsNames(functionsP) {
    let childrenNames = [];

    functionsP.forEach((f) => {
      if (childrenNames.find((name) => name === f.name)) return;

      f.children = [];
      for (const ff of functionsP) {
        if (ff.name !== f.name) {
          if (
            ff.startLine >= f.startLine &&
            ff.endLine >= f.startLine &&
            ff.startLine <= f.endLine &&
            ff.endLine <= f.endLine
          ) {
            f.children.push(ff);
            childrenNames.push(ff.name);
          }
        }
      }

      const secondLevelChildren = getChildrenFunctionsNames(f.children);

      f.children = f.children.filter(
        (fff) => !secondLevelChildren.find((name) => name === fff.name)
      );
    });

    return childrenNames;
  }

  const childrenFunctionNames = getChildrenFunctionsNames(functions);
  return functions.filter(
    (f) => !childrenFunctionNames.find((name) => name === f.name)
  );
};

export const getInnerMostVulnerableFunctions = (functions) => {
  let vulnerableFunctions = [];

  const processChildren = (functionsP) => {
    functionsP.forEach((f) => {
      if (f.isVuln) {
        vulnerableFunctions.push(f);
      }

      const currentNumberOfVulnFuncs = vulnerableFunctions.length;

      if (f.children.length > 0) {
        processChildren(f.children);
      }

      if (f.isVuln && vulnerableFunctions.length > currentNumberOfVulnFuncs)
        vulnerableFunctions.splice(currentNumberOfVulnFuncs - 1, 1);
    });
  };

  processChildren(functions);
  return vulnerableFunctions;
};

export const getFunctionNameWithLineNumer = (functions, lineNumber) => {
  const fs = functions
    .filter((f) => f.startLine <= lineNumber && f.endLine >= lineNumber)
    .sort((fA, fB) => fB.startLine - fA.startLine);
  return fs[0]?.name ?? lineNumber;
};
