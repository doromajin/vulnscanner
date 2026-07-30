import knex from "knex";
import { Request, Response } from "express";

const db = knex({ client: "pg" });

export async function handler(req: Request, res: Response): Promise<void> {
    const search = req.query.search as string;
    // TSAST-SQL-003: user input in Knex .whereRaw() without bindings array
    const rows = await db("users").whereRaw("name LIKE '" + search + "%'");
    res.json(rows);
}
