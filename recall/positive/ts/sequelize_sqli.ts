import { Sequelize } from "sequelize";
import { Request, Response } from "express";

const sequelize = new Sequelize("postgres://user:pass@localhost/db");

export async function handler(req: Request, res: Response): Promise<void> {
    const id = req.query.id as string;
    // TSAST-SQL-004: user input in sequelize.query()
    const [results] = await sequelize.query("SELECT * FROM users WHERE id = " + id);
    res.json(results);
}
