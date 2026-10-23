import { walkFiles, readText } from './files.js';
import { classifyFile, extractImports } from './context.js';

/**
 * Read the project's source once: classify every code file and index which packages it imports.
 * @returns {{files: {rel:string, kind:string, ext:string, context:string|null}[], texts: Map<string,string>,
 *   contexts: Map<string,string>, usage: Map<string, {file:string,line:number,context:string,binding:string|null,spec:string}[]>}}
 */
export function analyzeSource(project) {
  const files = walkFiles(project.root);
  const texts = new Map();
  const contexts = new Map();
  const usage = new Map();

  for (const f of files) {
    const text = readText(f.abs);
    if (text === null) continue;
    texts.set(f.rel, text);
    if (f.kind !== 'code') continue;
    f.context = classifyFile(f.rel, text, project.framework);
    contexts.set(f.rel, f.context);
    if (!/\.(php|py)$/.test(f.rel)) {
      for (const imp of extractImports(text)) {
        if (!usage.has(imp.pkg)) usage.set(imp.pkg, []);
        usage.get(imp.pkg).push({ file: f.rel, line: imp.line, context: f.context, binding: imp.binding, spec: imp.spec });
      }
    }
  }
  return { files, texts, contexts, usage };
}
