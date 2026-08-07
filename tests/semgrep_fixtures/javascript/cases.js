// Fixture for the JavaScript/TypeScript rules — see ../python/quality_cases.py for the
// marker format. Security and quality live in one file here because the rules share a
// language pair and the near-misses read better next to their match.
const crypto = require("crypto");
const cp = require("child_process");
const jwt = require("jsonwebtoken");

function codeExecution(userInput) {
  eval(userInput); // zanshin: zanshin-js-eval
  eval("1 + 1");
  new Function(userInput); // zanshin: zanshin-js-eval
  cp.exec(userInput); // zanshin: zanshin-js-child-process-exec
  cp.exec("ls -l");
  cp.execFile("ls", ["-l"]);
}

function domWriting(el, value) {
  el.innerHTML = value; // zanshin: zanshin-js-inner-html
  el.innerHTML = "<b>static</b>";
  el.textContent = value;
  document.write(value); // zanshin: zanshin-js-document-write
}

function routing(req, res) {
  res.redirect(req.query.next); // zanshin: zanshin-js-open-redirect
  res.redirect("/home");
}

function transport() {
  const options = { rejectUnauthorized: false }; // zanshin: zanshin-js-tls-reject-unauthorized
  crypto.createHash("md5"); // zanshin: zanshin-js-weak-hash
  crypto.createHash("sha256");
  return options;
}

function tokens(raw) {
  const sessionToken = Math.random().toString(36); // zanshin: zanshin-js-insecure-random-secret
  const jitter = Math.random();
  jwt.decode(raw); // zanshin: zanshin-js-jwt-decode-without-verify
  jwt.verify(raw, "key");
  return { sessionToken, jitter };
}

function qualityCases(a, b, items) {
  try { // zanshin: zanshin-js-empty-catch
    a();
  } catch (e) {
  }
  if (a == b) return 1; // zanshin: zanshin-js-loose-equality
  if (a === b) return 2;
  if (a == null) return 3;
  console.log("debug"); // zanshin: zanshin-js-console-log-left-behind
  debugger; // zanshin: zanshin-js-debugger-statement
  return items;
}

async function sequential(ids, fetchOne) {
  const out = [];
  for (const id of ids) {
    out.push(await fetchOne(id)); // zanshin: zanshin-js-await-in-loop
  }
  return out;
}

module.exports = { codeExecution, domWriting, routing, transport, tokens, qualityCases, sequential };
