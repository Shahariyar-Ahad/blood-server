// encode.js
const fs = require("fs");
const key = fs.readFileSync("./bd-blood-donar-2025-firebase-adminsdk-fbsvc-bdd8b35934.json", "utf8");
const base64 = Buffer.from(key).toString("base64");
console.log(base64);