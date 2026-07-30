import { getConnection } from "typeorm";
import { Request, Response } from "express";

export async function handler(req: Request, res: Response): Promise<void> {
    const id = req.query.id as string;
    const qb = getConnection().createQueryBuilder();
    // Safe: parameterized with :id binding object — second arg is the binding map
    const users = await qb.where("u.id = :id", { id }).getMany();
    res.json(users);
}
