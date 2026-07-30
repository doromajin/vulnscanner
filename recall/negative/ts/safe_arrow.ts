// Safe arrow function: parameterized query — JSAST-SQL-001 must NOT fire
import { Request, Response } from 'express';

const getParam = (req: Request, key: string): string =>
    req.query[key] as string;

export function handler(req: Request, res: Response) {
    const db = { query: (sql: string, params: unknown[]) => null };
    const id = getParam(req, 'id');
    db.query("SELECT * FROM users WHERE id = ?", [id]);
}
