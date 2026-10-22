import jwt from 'jsonwebtoken';
import axios from 'axios';
import _ from 'lodash';
import { exec } from 'child_process';

export async function GET(req: Request) {
  const url = new URL(req.url);
  const token = req.headers.get('authorization')?.slice(7) ?? '';
  const user = jwt.verify(token, process.env.JWT_SECRET!);

  // Render a greeting from a user-controlled template
  const greet = _.template(url.searchParams.get('tpl') ?? 'Hello <%= name %>');

  // Fetch avatar from a user-supplied URL
  const avatar = await axios.get(url.searchParams.get('avatar')!);

  exec(`convert ${url.searchParams.get('file')} out.png`);

  return Response.json({ user, greeting: greet({ name: 'x' }), size: avatar.data.length });
}
