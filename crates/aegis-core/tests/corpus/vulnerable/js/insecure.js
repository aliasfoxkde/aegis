// Node.js service showing the classic dangerous APIs.
const express = require("express");
const app = express();

app.post("/run", (req, res) => res.send(eval(req.body.expr))); // aegis:expect eval-usage code-quality-eval-usage

const { exec } = require("child_process");
exec("ls -la " + req.query.dir, (err, out) => console.log(out)); // aegis:expect command-injection console-log console-log-debug

db.query(`SELECT * FROM users WHERE id=${req.params.id}`); // aegis:expect express-sql-injection

debugger; // aegis:expect debugger-statement

const session_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"; // aegis:expect rust-hardcoded-secret

const githubToken = "ghp_Qk4bWk3nzFT8rYyE2oXvAeM1dJcUuS6hKpTn"; // aegis:expect github-token

const dbPassword = "sup3rs3cret-production-pw"; // aegis:expect hardcoded-password

console.log("server booted"); // aegis:expect console-log console-log-debug

module.exports = app;
