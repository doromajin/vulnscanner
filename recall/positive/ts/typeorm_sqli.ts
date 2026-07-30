import { getConnection } from "typeorm";
import { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const id = req.query.id as string;
    const qb = getConnection().createQueryBuilder();
    // TSAST-SQL-001: user input concatenated into TypeORM .where() raw string
    const users = await qb.where("u.id = '" + id + "'").getMany();
    res.json(users);
}
