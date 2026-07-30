// Interprocedural taint via arrow function: JSAST-SQL-001 must fire
import { Request, Response } from 'express';

const getParam = (req: Request, key: string): string =>
    req.query[key] as string;

export function handler(req: Request, res: Response) {
    const db = { query: (s: string) => s };
    const id = getParam(req, 'id');
    db.query("SELECT * FROM users WHERE id = '" + id + "'");
}
