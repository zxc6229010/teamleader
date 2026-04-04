const functions = require("firebase-functions");
const admin = require("firebase-admin");
const cors = require("cors")({ origin: true });

admin.initializeApp();

const db = admin.firestore();
const auth = admin.auth();

function nowMs() {
  return Date.now();
}

function requireMethod(req, res, method) {
  if (req.method !== method) {
    res.status(405).json({ error: "method_not_allowed" });
    return false;
  }
  return true;
}

function assertString(x, min = 1, max = 2000) {
  if (typeof x !== "string") return false;
  const s = x.trim();
  if (s.length < min) return false;
  if (s.length > max) return false;
  return true;
}

async function getUserDoc(uid) {
  const snap = await db.collection("users").doc(uid).get();
  return snap.exists ? snap.data() : null;
}

function hasPerm(userDoc, key) {
  return userDoc?.roles?.superAdmin === true || userDoc?.permissions?.[key] === true;
}

function isExpiredTimestamp(ts) {
  if (!ts) return true;
  const d = ts.toDate ? ts.toDate() : new Date(ts);
  return nowMs() > d.getTime();
}

function cleanEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function toBool(v, fallback = false) {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (["true", "1", "yes", "y"].includes(s)) return true;
    if (["false", "0", "no", "n"].includes(s)) return false;
  }
  return fallback;
}

function normalizeRoles(input = {}) {
  return {
    student: input.student === true,
    busLeader: input.busLeader === true,
    staff: input.staff === true,
    admin: input.admin === true,
    superAdmin: input.superAdmin === true,
  };
}

function inferTitleFromRoles(roles) {
  if (roles.superAdmin) return "超級管理員";
  if (roles.admin) return "行政";
  if (roles.staff) return "車長幹部";
  if (roles.busLeader) return "車長";
  return "學生";
}

async function emailExists(email) {
  try {
    await auth.getUserByEmail(email);
    return true;
  } catch (e) {
    if (e.code === "auth/user-not-found") return false;
    throw e;
  }
}

async function writeAuditLog(data) {
  try {
    await db.collection("auditLogs").add({
      at: admin.firestore.FieldValue.serverTimestamp(),
      ...data,
    });
  } catch (e) {
    console.error("[auditLogs]", e);
  }
}

/**
 * ✅ 重設密碼
 */
exports.resetPasswordWithToken = functions
  .region("us-central1")
  .https.onRequest((req, res) => {
    cors(req, res, async () => {
      if (!requireMethod(req, res, "POST")) return;

      try {
        const token = req.body?.token;
        const newPassword = req.body?.newPassword;

        if (!assertString(token, 10, 500)) {
          return res.status(400).json({ error: "invalid_token" });
        }
        if (!assertString(newPassword, 6, 200)) {
          return res.status(400).json({ error: "invalid_password" });
        }

        const tokenRef = db.collection("passwordResetTokens").doc(token);
        const tokenSnap = await tokenRef.get();
        if (!tokenSnap.exists) {
          return res.status(404).json({ error: "token_not_found" });
        }

        const t = tokenSnap.data() || {};
        if (t.used === true) {
          return res.status(400).json({ error: "token_already_used" });
        }
        if (t.purpose !== "password_reset") {
          return res.status(400).json({ error: "invalid_purpose" });
        }
        if (!t.uid || typeof t.uid !== "string") {
          return res.status(400).json({ error: "token_missing_uid" });
        }
        if (!t.expiresAt || isExpiredTimestamp(t.expiresAt)) {
          return res.status(400).json({ error: "token_expired" });
        }

        await auth.updateUser(t.uid, { password: newPassword });

        await db.runTransaction(async (tx) => {
          const again = await tx.get(tokenRef);
          if (!again.exists) throw new Error("token_missing");
          const cur = again.data() || {};
          if (cur.used === true) throw new Error("token_used");

          tx.set(
            tokenRef,
            {
              used: true,
              usedAt: admin.firestore.FieldValue.serverTimestamp(),
              usedFrom: req.ip || null,
            },
            { merge: true }
          );
        });

        return res.json({ ok: true });
      } catch (e) {
        console.error("[resetPasswordWithToken]", e);
        return res.status(500).json({ error: "internal_error" });
      }
    });
  });

/**
 * ✅ 建立單筆帳號
 * POST JSON:
 * {
 *   name, studentId, classSeat, email, title, password, enabled, roles
 * }
 */
exports.createUserAccount = functions
  .region("us-central1")
  .https.onRequest((req, res) => {
    cors(req, res, async () => {
      if (!requireMethod(req, res, "POST")) return;

      try {
        const idToken = (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
        if (!idToken) return res.status(401).json({ error: "missing_auth" });

        const decoded = await auth.verifyIdToken(idToken);
        const operatorUid = decoded.uid;
        const operatorDoc = await getUserDoc(operatorUid);

        if (!operatorDoc || operatorDoc.enabled !== true) {
          return res.status(403).json({ error: "operator_disabled" });
        }
        if (!hasPerm(operatorDoc, "admin.createUsers")) {
          return res.status(403).json({ error: "no_permission_create_users" });
        }

        const name = String(req.body?.name || "").trim();
        const studentId = String(req.body?.studentId || "").trim();
        const classSeat = String(req.body?.classSeat || "").trim();
        let email = cleanEmail(req.body?.email || "");
        let title = String(req.body?.title || "").trim();
        let password = String(req.body?.password || "").trim();
        const enabled = toBool(req.body?.enabled, true);
        const roles = normalizeRoles(req.body?.roles || {});

        if (!name) return res.status(400).json({ error: "missing_name" });

        const isStudentLike = roles.student === true;
        if (isStudentLike) {
          if (!studentId) return res.status(400).json({ error: "missing_studentId" });
          if (!email) email = `${studentId}@student.local`;
          if (!password) password = classSeat;
        }

        if (!email) return res.status(400).json({ error: "missing_email" });
        if (!password || password.length < 6) return res.status(400).json({ error: "invalid_password" });

        if (!title) {
          title = inferTitleFromRoles(roles);
        }

        const exists = await emailExists(email);
        if (exists) {
          return res.status(409).json({ error: "email_already_exists" });
        }

        const userRecord = await auth.createUser({
          email,
          password,
          displayName: name,
          disabled: !enabled,
        });

        const uid = userRecord.uid;

        await db.collection("users").doc(uid).set({
          name,
          email,
          studentId,
          classSeat,
          title,
          enabled,
          roles,
          permissions: {},
          authMeta: {
            creationTime: userRecord.metadata.creationTime || null,
            lastSignInTime: userRecord.metadata.lastSignInTime || null,
          },
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        await writeAuditLog({
          actorUid: operatorUid,
          action: "user.createOne",
          targetUid: uid,
          targetEmail: email,
          targetName: name,
        });

        return res.json({
          ok: true,
          uid,
          email,
        });
      } catch (e) {
        console.error("[createUserAccount]", e);

        if (e.code === "auth/email-already-exists") {
          return res.status(409).json({ error: "email_already_exists" });
        }
        return res.status(500).json({ error: "internal_error" });
      }
    });
  });

/**
 * ✅ 批次建立帳號
 * POST JSON:
 * {
 *   rows: [
 *     {
 *       name, studentId, classSeat, email, title,
 *       student, busLeader, staff, admin, superAdmin,
 *       password, enabled
 *     }
 *   ],
 *   defaultPassword
 * }
 */
exports.bulkCreateUserAccounts = functions
  .region("us-central1")
  .runWith({ timeoutSeconds: 540, memory: "1GB" })
  .https.onRequest((req, res) => {
    cors(req, res, async () => {
      if (!requireMethod(req, res, "POST")) return;

      try {
        const idToken = (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
        if (!idToken) return res.status(401).json({ error: "missing_auth" });

        const decoded = await auth.verifyIdToken(idToken);
        const operatorUid = decoded.uid;
        const operatorDoc = await getUserDoc(operatorUid);

        if (!operatorDoc || operatorDoc.enabled !== true) {
          return res.status(403).json({ error: "operator_disabled" });
        }
        if (!hasPerm(operatorDoc, "admin.bulkCreateUsers")) {
          return res.status(403).json({ error: "no_permission_bulk_create_users" });
        }

        const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
        const defaultPassword = String(req.body?.defaultPassword || "").trim();

        if (!rows.length) {
          return res.status(400).json({ error: "missing_rows" });
        }
        if (rows.length > 500) {
          return res.status(400).json({ error: "too_many_rows" });
        }

        const results = [];
        let successCount = 0;
        let failedCount = 0;

        for (let i = 0; i < rows.length; i++) {
          const raw = rows[i] || {};

          try {
            const name = String(raw.name || "").trim();
            const studentId = String(raw.studentId || "").trim();
            const classSeat = String(raw.classSeat || "").trim();
            let email = cleanEmail(raw.email || "");
            let title = String(raw.title || "").trim();
            let password = String(raw.password || "").trim();
            const enabled = toBool(raw.enabled, true);

            const roles = normalizeRoles({
              student: toBool(raw.student, false),
              busLeader: toBool(raw.busLeader, false),
              staff: toBool(raw.staff, false),
              admin: toBool(raw.admin, false),
              superAdmin: toBool(raw.superAdmin, false),
            });

            if (!name) throw new Error("missing_name");

            const isStudentLike = roles.student === true;
            if (isStudentLike) {
              if (!studentId) throw new Error("missing_studentId");
              if (!email) email = `${studentId}@student.local`;
              if (!password) password = classSeat;
            } else {
              if (!email) throw new Error("missing_email");
              if (!password) password = defaultPassword;
            }

            if (!title) title = inferTitleFromRoles(roles);
            if (!password || password.length < 6) throw new Error("invalid_password");

            const exists = await emailExists(email);
            if (exists) throw new Error("email_already_exists");

            const userRecord = await auth.createUser({
              email,
              password,
              displayName: name,
              disabled: !enabled,
            });

            await db.collection("users").doc(userRecord.uid).set({
              name,
              email,
              studentId,
              classSeat,
              title,
              enabled,
              roles,
              permissions: {},
              authMeta: {
                creationTime: userRecord.metadata.creationTime || null,
                lastSignInTime: userRecord.metadata.lastSignInTime || null,
              },
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            }, { merge: true });

            results.push({
              index: i + 1,
              ok: true,
              uid: userRecord.uid,
              email,
              name,
            });
            successCount++;
          } catch (e) {
            console.error("[bulkCreateUserAccounts:item]", i + 1, e);
            results.push({
              index: i + 1,
              ok: false,
              name: raw?.name || "",
              email: raw?.email || "",
              error: e.message || "unknown_error",
            });
            failedCount++;
          }
        }

        await writeAuditLog({
          actorUid: operatorUid,
          action: "user.bulkCreate",
          successCount,
          failedCount,
          total: rows.length,
        });

        return res.json({
          ok: true,
          total: rows.length,
          successCount,
          failedCount,
          results,
        });
      } catch (e) {
        console.error("[bulkCreateUserAccounts]", e);
        return res.status(500).json({ error: "internal_error" });
      }
    });
  });

/**
 * ✅ 模擬身份：建立 session
 */
exports.createImpersonationSession = functions
  .region("us-central1")
  .https.onRequest((req, res) => {
    cors(req, res, async () => {
      if (!requireMethod(req, res, "POST")) return;

      try {
        const idToken = (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
        if (!idToken) return res.status(401).json({ error: "missing_auth" });

        const decoded = await auth.verifyIdToken(idToken);
        const operatorUid = decoded.uid;

        const operatorDoc = await getUserDoc(operatorUid);
        if (!operatorDoc || operatorDoc.enabled !== true) return res.status(403).json({ error: "operator_disabled" });
        if (!hasPerm(operatorDoc, "admin.impersonate")) return res.status(403).json({ error: "no_permission" });

        const target = req.body?.target;
        const mode = req.body?.mode;
        const expiresInMin = Number(req.body?.expiresInMin || 10);

        if (!assertString(target, 1, 200)) return res.status(400).json({ error: "invalid_target" });
        if (!["studentId", "email", "uid"].includes(mode)) return res.status(400).json({ error: "invalid_mode" });
        if (!(expiresInMin >= 1 && expiresInMin <= 60)) return res.status(400).json({ error: "invalid_expires" });

        let targetUid = null;

        if (mode === "uid") {
          targetUid = target.trim();
        } else if (mode === "email") {
          const q = await db.collection("users").where("email", "==", target.trim()).limit(1).get();
          targetUid = q.empty ? null : q.docs[0].id;
        } else if (mode === "studentId") {
          const q = await db.collection("users").where("studentId", "==", target.trim()).limit(1).get();
          targetUid = q.empty ? null : q.docs[0].id;
        }

        if (!targetUid) return res.status(404).json({ error: "target_not_found" });

        const targetDoc = await getUserDoc(targetUid);
        if (!targetDoc || targetDoc.enabled !== true) return res.status(400).json({ error: "target_disabled" });

        const expiresAt = new Date(nowMs() + expiresInMin * 60 * 1000);

        const sessionRef = db.collection("impersonationSessions").doc();
        const sessionId = sessionRef.id;

        await sessionRef.set({
          sessionId,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
          used: false,
          createdByUid: operatorUid,
          targetUid,
          targetSnapshot: {
            name: targetDoc.name || "",
            title: targetDoc.title || "",
            studentId: targetDoc.studentId || "",
            email: targetDoc.email || "",
            roles: targetDoc.roles || {},
          },
          purpose: "impersonate_login",
        });

        await writeAuditLog({
          actorUid: operatorUid,
          action: "impersonation.createSession",
          targetUid,
          sessionId,
          ip: req.ip || null,
          ua: req.headers["user-agent"] || null,
        });

        return res.json({
          ok: true,
          sessionId,
          expiresAt: expiresAt.toISOString(),
        });
      } catch (e) {
        console.error("[createImpersonationSession]", e);
        return res.status(500).json({ error: "internal_error" });
      }
    });
  });

/**
 * ✅ 模擬身份：交換 custom token
 */
exports.exchangeImpersonationSession = functions
  .region("us-central1")
  .https.onRequest((req, res) => {
    cors(req, res, async () => {
      if (!requireMethod(req, res, "POST")) return;

      try {
        const sessionId = req.body?.sessionId;
        if (!assertString(sessionId, 5, 200)) return res.status(400).json({ error: "invalid_sessionId" });

        const sessionRef = db.collection("impersonationSessions").doc(sessionId);

        const result = await db.runTransaction(async (tx) => {
          const snap = await tx.get(sessionRef);
          if (!snap.exists) return { ok: false, error: "session_not_found" };
          const s = snap.data() || {};

          if (s.used === true) return { ok: false, error: "session_used" };
          if (!s.expiresAt || isExpiredTimestamp(s.expiresAt)) return { ok: false, error: "session_expired" };
          if (!s.targetUid) return { ok: false, error: "session_invalid" };

          tx.set(
            sessionRef,
            {
              used: true,
              usedAt: admin.firestore.FieldValue.serverTimestamp(),
              usedFrom: req.ip || null,
            },
            { merge: true }
          );

          return { ok: true, targetUid: s.targetUid, roles: s.targetSnapshot?.roles || {} };
        });

        if (!result.ok) {
          return res.status(400).json({ error: result.error });
        }

        const customToken = await auth.createCustomToken(result.targetUid, {
          impersonated: true,
          iatMs: nowMs(),
        });

        return res.json({
          ok: true,
          customToken,
          targetUid: result.targetUid,
          roles: result.roles || {},
        });
      } catch (e) {
        console.error("[exchangeImpersonationSession]", e);
        return res.status(500).json({ error: "internal_error" });
      }
    });
  });