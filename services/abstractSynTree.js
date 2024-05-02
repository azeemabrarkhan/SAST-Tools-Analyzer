import esTree from "@typescript-eslint/typescript-estree";
import AbstractSyntaxTree from "abstract-syntax-tree";

export default class AbstractSynTree {
  getFunctionsLocation = (sourceCode) => {
    const getLocationsUsingEsTree = () => {
      const functionalNodes = [];

      const processNode = (node) => {
        if (
          node.type === "FunctionDeclaration" ||
          node.type === "FunctionExpression" ||
          node.type === "ArrowFunctionExpression"
        ) {
          functionalNodes.push({
            name: `function${functionalNodes.length}`,
            type: node.type,
            startLine: node.loc.start.line,
            endLine: node.loc.end.line,
          });
          processNode(node.body);
        } else if (node.type === "ExpressionStatement") {
          processNode(node.expression);
        } else if (node.type === "VariableDeclarator") {
          processNode(node.init);
        } else {
          const childNodes =
            node.type === "VariableDeclaration" ? node.declarations : node.body;
          for (const bodyNode in childNodes) {
            processNode(childNodes[bodyNode]);
          }
        }
      };

      const getAST = () => {
        return esTree.parse(sourceCode, {
          errorOnUnknownASTType: false,
          allowInvalidAST: true,
          jsx: true,
          loc: true,
          // filePath
        });
      };

      const tree = getAST();
      processNode(tree);

      return functionalNodes;
    };

    const getLocationsUsingAST = () => {
      const tree = new AbstractSyntaxTree(sourceCode);
      const functionDeclarations = tree
        .find("FunctionDeclaration")
        .map((node) => ({
          type: "FunctionDeclaration",
          startLine: node?.loc?.start?.line,
          endLine: node?.loc?.end?.line,
        }));
      const functionExpressions = tree
        .find("FunctionExpression")
        .map((node) => ({
          type: "FunctionExpression",
          startLine: node?.loc?.start?.line,
          endLine: node?.loc?.end?.line,
        }));
      const arrowFunctionExpressions = tree
        .find("ArrowFunctionExpression")
        .map((node) => ({
          type: "ArrowFunctionExpression",
          startLine: node?.loc?.start?.line,
          endLine: node?.loc?.end?.line,
        }));

      const functionalNodes = [
        ...functionDeclarations,
        ...functionExpressions,
        ...arrowFunctionExpressions,
      ]
        .sort((a, b) => a.startLine - b.startLine)
        .map((f, index) => ({ name: `function${index}`, ...f }));

      return functionalNodes;
    };

    let functionalNodes = [];
    let errorMessage;
    try {
      functionalNodes = getLocationsUsingAST();
    } catch (err) {
      errorMessage = err;
    }
    if (functionalNodes.length === 0) {
      try {
        functionalNodes = getLocationsUsingEsTree();
      } catch (err) {
        errorMessage = errorMessage + " OR " + err;
      }
    }
    if (functionalNodes.length === 0) {
      throw new Error(errorMessage);
    } else {
      return functionalNodes;
    }
  };
}
