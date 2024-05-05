import esTree from "@typescript-eslint/typescript-estree";
import AbstractSyntaxTree from "abstract-syntax-tree";

export default class AbstractSynTree {
  getFunctionsLocations = (sourceCode) => {
    const getLocationsUsingEsTree = (isJSX) => {
      const functionalNodes = [];

      const processNode = (node) => {
        if (node === null) {
          return;
        } else if (
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
        } else if (node.type === "AssignmentExpression") {
          processNode(node.right);
        } else if (
          node.type === "ExportNamedDeclaration" ||
          node.type === "ExportDefaultDeclaration"
        ) {
          processNode(node.declaration);
        } else if (node.type === "VariableDeclarator") {
          processNode(node.init);
        } else if (node.type === "MethodDefinition") {
          processNode(node.value);
        } else {
          const childNodes =
            node.type === "VariableDeclaration"
              ? node.declarations
              : node.type === "ClassDeclaration"
              ? node.body.body
              : node.type === "IfStatement"
              ? node.consequent.body
              : node.type === "CallExpression"
              ? node.arguments
              : node.body;
          for (const bodyNode in childNodes) {
            processNode(childNodes[bodyNode]);
          }
        }
      };

      const getAST = () => {
        return esTree.parse(sourceCode, {
          errorOnUnknownASTType: false,
          allowInvalidAST: true,
          jsx: isJSX,
          loc: true,
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
        functionalNodes = getLocationsUsingEsTree(true);
      } catch (err) {
        errorMessage = errorMessage + " OR " + err;
      }
    }
    if (functionalNodes.length === 0) {
      try {
        functionalNodes = getLocationsUsingEsTree(false);
      } catch (err) {
        errorMessage = errorMessage + " OR " + err;
        throw new Error(errorMessage);
      }
    }

    return functionalNodes;
  };
}
