// Safe object method: returns a constant — JSAST-SQL-001 must NOT fire
// The method does NOT return user-controlled data, so taint must not propagate.
'use strict';

const helpers = {
    getDefaultRole() {
        return 'viewer';  // constant, no user input
    },
};

function handler(req, res) {
    const db = { query: (sql, params) => null };
    const role = helpers.getDefaultRole();
    db.query('SELECT * FROM users WHERE role = ?', [role]);
}
