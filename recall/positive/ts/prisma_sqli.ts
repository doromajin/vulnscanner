import { PrismaClient } from "@prisma/client";
import { Request, Response } from "express";

const prisma = new PrismaClient();

export async function handler(req: Request, res: Response): Promise<void> {
    const id = req.query.id as string;
    // TSAST-SQL-002: user input in Prisma $queryRawUnsafe (CRITICAL)
    const result = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + id);
    res.json(result);
}
