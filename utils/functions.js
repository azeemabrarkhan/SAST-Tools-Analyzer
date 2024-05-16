export const convertFunctionsInHierarchicalStructure = (functions) => {
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
