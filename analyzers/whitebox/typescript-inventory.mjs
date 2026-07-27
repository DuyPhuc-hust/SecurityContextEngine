import ts from "typescript";
import { join, resolve } from "node:path";
import { trackedGitFiles } from "../../adapters/git/inventory.mjs";

const routeMethods = new Set(["get", "post", "put", "patch", "delete", "all", "use"]);
const sinkNames = new Set(["eval", "exec", "execSync", "spawn", "spawnSync", "query", "execute", "$queryRaw", "writeFile", "writeFileSync", "redirect"]);
const authTerms = /auth|authorize|permission|role|ownership|tenant|session/i;
const validationTerms = /validat|saniti|escape|safeparse|parse|schema/i;

const lineOf = (source, node) => source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
const textOf = (source, node) => node.getText(source).slice(0, 240);
const callName = (expression) => ts.isPropertyAccessExpression(expression) ? expression.name.text : ts.isIdentifier(expression) ? expression.text : "";
const expressionName = (expression) => ts.isPropertyAccessExpression(expression) ? expression.getText() : ts.isIdentifier(expression) ? expression.text : "";

function classifyCall(name) {
  if (sinkNames.has(name)) return "sink";
  if (authTerms.test(name)) return "auth-control";
  if (validationTerms.test(name)) return "validation-control";
  return null;
}

export async function extractTypeScriptInventory(repositoryRoot) {
  const root = resolve(repositoryRoot);
  const files = (await trackedGitFiles(root)).filter((file) => /\.(?:[cm]?ts|[cm]?js|tsx|jsx)$/.test(file));
  const result = { version: "typescript-inventory/v1", repository_root: root, files: [], symbols: [], imports: [], routes: [], sources: [], sinks: [], controls: [], edges: [] };

  for (const relativePath of files) {
    const path = join(root, relativePath);
    const source = ts.createSourceFile(path, ts.sys.readFile(path) ?? "", ts.ScriptTarget.Latest, true);
    result.files.push({ path: relativePath, language: source.scriptKind === ts.ScriptKind.JSX || source.scriptKind === ts.ScriptKind.TSX ? "TypeScript/JSX" : "TypeScript/JavaScript" });
    const visit = (node) => {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        result.imports.push({ file: relativePath, module: node.moduleSpecifier.text, line: lineOf(source, node) });
        result.edges.push({ kind: "IMPORTS", from: relativePath, to: node.moduleSpecifier.text, line: lineOf(source, node) });
      }
      if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isMethodDeclaration(node)) && node.name) {
        result.symbols.push({ id: `${relativePath}:${node.name.getText(source)}:${lineOf(source, node)}`, file: relativePath, name: node.name.getText(source), kind: ts.SyntaxKind[node.kind], line: lineOf(source, node) });
      }
      if (ts.isCallExpression(node)) {
        const name = callName(node.expression);
        const target = expressionName(node.expression);
        const line = lineOf(source, node);
        if (ts.isPropertyAccessExpression(node.expression) && routeMethods.has(name) && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])) {
          const middleware = node.arguments.slice(1, -1).map((argument) => textOf(source, argument));
          const route = { file: relativePath, method: name.toUpperCase(), path: node.arguments[0].text, handler: node.arguments.at(-1) ? textOf(source, node.arguments.at(-1)) : null, middleware, line };
          result.routes.push(route);
          result.edges.push({ kind: "EXPOSES", from: relativePath, to: `${route.method} ${route.path}`, line });
        }
        const classification = classifyCall(name);
        if (classification === "sink") result.sinks.push({ file: relativePath, name, target, line });
        if (classification === "auth-control" || classification === "validation-control") result.controls.push({ file: relativePath, kind: classification, name, target, line });
      }
      if (ts.isPropertyAccessExpression(node)) {
        const value = node.getText(source);
        if (/^(req|request)\.(body|params|query|headers|cookies)/.test(value)) result.sources.push({ file: relativePath, kind: "http-input", expression: value, line: lineOf(source, node) });
        if (/^process\.env\./.test(value)) result.sources.push({ file: relativePath, kind: "configuration", expression: value, line: lineOf(source, node) });
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return result;
}
