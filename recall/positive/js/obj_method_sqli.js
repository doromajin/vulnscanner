// Interprocedural taint via object method: JSAST-SQL-001 must fire
'use strict';

const helpers = {
    getInput(req) {
        return req.body.name;
    },
};

function handler(req, res) {
    const db = { query: (s) => s };
    const name = helpers.getInput(req);
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
}
