import { PrismaClient } from "@prisma/client";
import { Request, Response } from "express";

const prisma = new PrismaClient();

export async function handler(req: Request, res: Response): Promise<void> {
    const id = req.query.id as string;
    // Safe: Prisma parameterized findMany (no raw SQL)
    const user = await prisma.user.findMany({ where: { id } });
    res.json(user);
}
