/**
 * Seed / 初始化 Firestore 結構（穩定版）
 *
 * 用法：
 *   npm i firebase-admin
 *   node seed-firestore.js --semester=114-1 --uid=你的UID --name=劉瑜晉 --title=超級管理員
 *
 * 可選：
 *   node seed-firestore.js --serviceAccount=./serviceAccount.json --semester=114-1 --uid=xxx
 */

const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

const args = Object.fromEntries(
  process.argv.slice(2).map((x) => {
    const [k, v] = x.replace(/^--/, "").split("=");
    return [k, v ?? true];
  })
);

const SERVICE_ACCOUNT_PATH = String(args.serviceAccount || "./serviceAccount.json");

const semesterId = String(args.semester || "114-1").trim();
const uid = String(args.uid || "").trim();
const name = String(args.name || "未命名").trim();
const title = String(args.title || "未設定職稱").trim();

function mustFile(p) {
  const fp = path.resolve(process.cwd(), p);
  if (!fs.existsSync(fp)) {
    throw new Error(
      `找不到 service account 檔案：${fp}\n` +
      `請把 serviceAccount.json 放到專案根目錄，或用 --serviceAccount=路徑 指定`
    );
  }
  return fp;
}

const serviceAccountFile = mustFile(SERVICE_ACCOUNT_PATH);
const serviceAccount = require(serviceAccountFile);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

function nowTs() {
  return admin.firestore.Timestamp.now();
}

async function ensureDoc(ref, data, { merge = true } = {}) {
  await ref.set(data, { merge });
}

async function run() {
  console.log("== Seed start ==");
  console.log("semesterId:", semesterId);
  console.log("uid:", uid || "(未提供，不會修改 users/{uid})");
  console.log("serviceAccount:", serviceAccountFile);

  // -----------------------------
  // 1) settings/global（dashboard 會讀）
  // -----------------------------
  await ensureDoc(db.collection("settings").doc("global"), {
    active_semester_id: semesterId,
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 2) config/system（你也有留著用）
  // -----------------------------
  await ensureDoc(db.collection("config").doc("system"), {
    currentSemester: semesterId,
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 3) semesters/{semesterId} 主文件
  // -----------------------------
  const semRef = db.collection("semesters").doc(semesterId);

  // 不要每次都覆蓋 createdAt：用 merge + 只更新 updatedAt
  // （第一次沒有時，createdAt 會被寫入；第二次以後不會動）
  await ensureDoc(semRef, {
    semesterId,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 3-1) meta/dashboard：儀表板統計
  // -----------------------------
  await ensureDoc(semRef.collection("meta").doc("dashboard"), {
    todayMode: "未設定", // 上學 / 週一～週四小放學 / 週五小放學 / 大放學
    routes: {
      batch1Total: 0,
      batch2Total: 0,
      nearFullRoutes: 0,
      updatedAt: nowTs(),
    },
    violations: {
      todayCount: 0,
      weekCount: 0,
      pendingCount: 0,
      updatedAt: nowTs(),
    },
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 3-2) meta/importStatus：四種車表匯入狀態
  // -----------------------------
  await ensureDoc(semRef.collection("meta").doc("importStatus"), {
    schoolAM: { imported: false, importedAt: null, source: "", note: "" }, // 上學
    pmMonThu: { imported: false, importedAt: null, source: "", note: "" }, // 週一～四小放學
    pmFri: { imported: false, importedAt: null, source: "", note: "" },    // 週五小放學
    pmBig: { imported: false, importedAt: null, source: "", note: "" },    // 大放學
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 3-3) meta/announcement：公告（跑馬燈 + 樣式）
  // -----------------------------
  await ensureDoc(semRef.collection("meta").doc("announcement"), {
    enabled: false,
    text: "",
    style: {
      color: "#111827",
      bold: false,
      italic: false,
      underline: false,
    },
    pages: {
      home: true,
      import: false,
      violation: false,
      query: false,
      audit: false,
      settings: false,
    },
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 3-4) meta/notifications：通知中心（行政總覽提示用）
  // -----------------------------
  await ensureDoc(semRef.collection("meta").doc("notifications"), {
    unreadCountForAdmin: 0,
    updatedAt: nowTs(),
  });

  // -----------------------------
  // 4) users/{uid}（只補缺，不亂蓋）
  // -----------------------------
  if (uid && uid !== "undefined" && uid !== "null") {
    const userRef = db.collection("users").doc(uid);

    // 只補缺：用點狀欄位，避免覆蓋你原本 roles/permissions 的整包
    await ensureDoc(userRef, {
      enabled: true,
      name,
      title,

      // roles.*
      "roles.superAdmin": true,
      "roles.admin": true,
      "roles.staff": true,
      "roles.busLeader": true,
      "roles.student": true,

      // permissions.*
      "permissions.admin.editViolations": true,
      "permissions.admin.exportReports": true,
      "permissions.admin.viewAllViolations": true,
      "permissions.busLeader.reportViolation": true,
      "permissions.staff.printViolationForms": true,
      "permissions.staff.recordViolation": true,
      "permissions.staff.voidViolation": true,
      "permissions.student.viewSelf": true,

      // timestamps
      updatedAt: nowTs(),
    });

    // createdAt：只在沒有時才會補（merge + serverTimestamp 不會破壞已存在的 createdAt）
    await ensureDoc(userRef, {
      createdAt: FieldValue.serverTimestamp(),
    });

    console.log(`✅ users/${uid} 已補齊 enabled/name/title/roles/permissions`);
  } else {
    console.log("⚠️ 沒帶 --uid，所以不會修改 users/{uid}");
  }

  console.log("== Seed done ==");
  console.log(`✅ 已建立/補齊：
- settings/global
- config/system
- semesters/${semesterId}
- semesters/${semesterId}/meta/dashboard
- semesters/${semesterId}/meta/importStatus
- semesters/${semesterId}/meta/announcement
- semesters/${semesterId}/meta/notifications
`);
}

run().catch((e) => {
  console.error("Seed failed:", e);
  process.exit(1);
});