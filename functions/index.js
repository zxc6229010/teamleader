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

/**
 * ✅ 重設密碼（真的改 Firebase Auth 密碼）
 * POST JSON: { token, newPassword }
 * token 讀取 passwordResetTokens/{token}
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

        // ✅ 更新 Auth 密碼
        await auth.updateUser(t.uid, { password: newPassword });

        // ✅ 標記 token 使用（transaction 避免競態）
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
 * ✅ 模擬身份：建立一次性 session
 * - 需要已登入且有 admin.impersonate 權限（或 superAdmin）
 * POST JSON: { target: "學號 或 email 或 uid", mode: "studentId|email|uid", expiresInMin?: number }
 * 回傳：{ sessionId, expiresAt }
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
        const mode = req.body?.mode; // studentId | email | uid
        const expiresInMin = Number(req.body?.expiresInMin || 10);

        if (!assertString(target, 1, 200)) return res.status(400).json({ error: "invalid_target" });
        if (!["studentId", "email", "uid"].includes(mode)) return res.status(400).json({ error: "invalid_mode" });
        if (!(expiresInMin >= 1 && expiresInMin <= 60)) return res.status(400).json({ error: "invalid_expires" });

        // 找目標 uid（以你 users collection 存的欄位為準：studentId / email）
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

        // ✅ 身份模擬範圍限制（你要的：管理層可模擬學生；由權限控制）
        // 這邊只做最基本：如果要更細「哪種身份可模擬哪種身份」我後面 rules/頁面也做了。
        // 你也可以用 targetDoc.roles 判斷要導去哪個頁面（student.html / dashboard.html…）
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
          // 可加你要的目的
          purpose: "impersonate_login",
        });

        // audit log
        await db.collection("auditLogs").add({
          at: admin.firestore.FieldValue.serverTimestamp(),
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
 * ✅ 模擬身份：用 sessionId 交換 customToken（一次性）
 * POST JSON: { sessionId }
 * 回傳：{ customToken, targetUid, roles }
 *
 * 注意：這個 API 不需要登入（因為是學生端/或管理員開新分頁用）
 * 安全性靠 sessionId 隨機性 + 短效 + 一次性
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

        // transaction：確保一次性
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

        // ✅ 產生 custom token（可在前端用 signInWithCustomToken 登入目標身份）
        // custom claims 這裡不改，避免權限混亂；權限一律看 Firestore users doc
        const customToken = await auth.createCustomToken(result.targetUid, {
          impersonated: true,
          // 你可以加上標記
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