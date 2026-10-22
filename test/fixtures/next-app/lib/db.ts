import { Pool } from 'pg';
import jwt from 'jsonwebtoken';

const pool = new Pool({ connectionString: 'postgres://admin:S3cr3tPassw0rd!@db.internal:5432/app' });

export async function findUser(req: Request) {
  const { searchParams } = new URL(req.url);
  const email = searchParams.get('email');
  // const old = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);  <- commented out, must not fire
  const rows = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);
  return rows;
}

export function issueToken(userId: string) {
  const resetToken = Math.random().toString(36).slice(2);
  return jwt.sign({ userId, resetToken }, 'my-super-secret-signing-key');
}

export const STRIPE_KEY = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
