// Mongoose-style User model.
//
// Backed by an in-memory store so the fixture runs without a live MongoDB, but
// it faithfully reproduces Mongoose's *vulnerable* query behavior: an operator
// object like {"$ne": null} in a query matches like real Mongo would — which is
// exactly what makes NoSQL injection (auth bypass) work here.
const USERS = [
  { _id: 1, username: "alice", password: "alice123", role: "user", email: "alice@chat.io" },
  { _id: 2, username: "bob", password: "bobsecret", role: "user", email: "bob@chat.io" },
  { _id: 3, username: "admin", password: "S3cr3tAdminP@ss", role: "admin", email: "admin@chat.io" },
];

function matchValue(actual, cond) {
  if (cond && typeof cond === "object") {
    if ("$ne" in cond) return actual !== cond["$ne"];
    if ("$gt" in cond) return actual > cond["$gt"];
    if ("$gte" in cond) return actual >= cond["$gte"];
    if ("$in" in cond) return Array.isArray(cond["$in"]) && cond["$in"].includes(actual);
    if ("$regex" in cond) return new RegExp(cond["$regex"]).test(String(actual));
    return false;
  }
  return actual === cond;
}

function matches(doc, query) {
  return Object.keys(query).every((k) => matchValue(doc[k], query[k]));
}

// Stored, mutable collections so the fixture can exercise stored-XSS and
// mass-assignment sinks against persistent state.
const COMMENTS = [];

module.exports = {
  USERS,
  COMMENTS,
  // VULN sink: if the query object is built from untrusted req.body, operator
  // injection bypasses authentication.
  findOne: async (query) => USERS.find((u) => matches(u, query)) || null,
  find: async (query) => USERS.filter((u) => matches(u, query || {})),
  findById: async (id) => USERS.find((u) => String(u._id) === String(id)) || null,
  // VULN sink: callers spread untrusted req.body straight into the record
  // (mass assignment / privilege escalation, CWE-915).
  updateById: async (id, patch) => {
    const u = USERS.find((x) => String(x._id) === String(id));
    if (!u) return null;
    Object.assign(u, patch);
    return u;
  },
  addComment: async (comment) => {
    COMMENTS.push(comment);
    return comment;
  },
  listComments: async () => COMMENTS,
};
