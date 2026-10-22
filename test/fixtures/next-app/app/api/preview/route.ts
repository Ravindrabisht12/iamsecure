import fs from 'fs';
import path from 'path';

export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get('name')!;
  const body = fs.readFileSync(path.join(process.cwd(), 'content', name), 'utf8');
  return new Response(body);
}
