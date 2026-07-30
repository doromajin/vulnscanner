// Interprocedural taint via async arrow function: JSAST-SQL-001 must fire

const getInput = async (req: any): Promise<string> => {
    return req.query.name as string;
};

export async function handler(req: any, res: any) {
    const db = { query: (s: string) => s };
    const name = await getInput(req);
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
}
