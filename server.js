/*************************************************
 * CASA TRADE – FULL BACKEND (SINGLE FILE)
 *************************************************/

const express = require("express");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");

/* ================= APP ================= */

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors());

/* ================= FIREBASE ================= */

admin.initializeApp({
  credential: admin.credential.applicationDefault()
});

const db = admin.firestore();

/* ================= CONFIG ================= */

const CASA_MAX_SUPPLY = 5_000_000;
const ESCROW_TIMEOUT = 45 * 60 * 1000;

const ADMIN_EMAIL = "ebubechichukwu8@gmail.com";
const ADMIN_PASSWORD = "Ebube@123";
const JWT_SECRET = "CHANGE_THIS_SECRET";

/* ================= RATE LIMIT ================= */

const rateMemory = {};

function rateLimit(uid, key, limit, windowMs) {
  const now = Date.now();
  rateMemory[uid] = rateMemory[uid] || {};
  rateMemory[uid][key] = (rateMemory[uid][key] || []).filter(t => now - t < windowMs);
  if (rateMemory[uid][key].length >= limit) throw "Rate limit exceeded";
  rateMemory[uid][key].push(now);
}

/* ================= LEDGER ================= */

async function ledger(from, to, amount, type, ref) {
  await db.collection("casa_ledger").add({
    from, to, amount, type, ref,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

/* ================= AUTH ================= */

function userAuth(req, res, next) {
  const uid = req.headers["x-user-id"];
  if (!uid) return res.status(401).send("Auth required");
  req.uid = uid;
  next();
}

function adminAuth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") throw "Forbidden";
    next();
  } catch {
    res.status(401).send("Invalid admin token");
  }
}

/* ================= ADMIN LOGIN ================= */

app.post("/admin/login", (req, res) => {
  const { email, password } = req.body;
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).send("Invalid credentials");
  }
  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "6h" });
  res.json({ token });
});

/* ================= CASA TRANSFER ================= */

app.post("/transfer", userAuth, async (req, res) => {
  try {
    rateLimit(req.uid, "transfer", 5, 60000);

    const { toEmail, amount } = req.body;
    const senderRef = db.collection("users").doc(req.uid);
    const sender = (await senderRef.get()).data();

    if (sender.banned) return res.status(403).send("Account banned");
    if (sender.casaBalance < amount) return res.status(400).send("Insufficient CASA");

    const snap = await db.collection("users").where("email", "==", toEmail).get();
    if (snap.empty) return res.status(404).send("User not found");

    const receiverRef = snap.docs[0].ref;

    await senderRef.update({ casaBalance: sender.casaBalance - amount });
    await receiverRef.update({ casaBalance: admin.firestore.FieldValue.increment(amount) });

    await ledger(req.uid, receiverRef.id, amount, "transfer", null);
    res.send("Transfer successful");
  } catch (e) {
    res.status(429).send(e.toString());
  }
});

/* ================= P2P AD ================= */

app.post("/p2p/ad", userAuth, async (req, res) => {
  const { casaAmount, country, banks, price } = req.body;
  const userRef = db.collection("users").doc(req.uid);
  const user = (await userRef.get()).data();

  if (user.casaBalance < casaAmount) return res.status(400).send("Insufficient CASA");

  await userRef.update({
    casaBalance: user.casaBalance - casaAmount,
    lockedCasa: admin.firestore.FieldValue.increment(casaAmount)
  });

  const adId = uuidv4();
  await db.collection("p2p_ads").doc(adId).set({
    owner: req.uid, casaAmount, country, banks, price,
    active: true,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  res.json({ adId });
});

/* ================= P2P BUY (ESCROW) ================= */

app.post("/p2p/buy", userAuth, async (req, res) => {
  rateLimit(req.uid, "p2p", 3, 600000);

  const { adId, casaAmount } = req.body;
  const ad = (await db.collection("p2p_ads").doc(adId).get()).data();
  if (!ad || !ad.active) return res.status(404).send("Ad unavailable");

  const orderId = uuidv4();
  await db.collection("p2p_orders").doc(orderId).set({
    adId,
    buyer: req.uid,
    seller: ad.owner,
    casaAmount,
    status: "INITIATED",
    expiresAt: Date.now() + ESCROW_TIMEOUT,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  sendSystemMessage(orderId, "Escrow started. Buyer has 45 minutes.");
  res.json({ orderId });
});

/* ================= CONFIRM PAYMENT ================= */

app.post("/p2p/confirm", userAuth, async (req, res) => {
  const { orderId } = req.body;
  const orderRef = db.collection("p2p_orders").doc(orderId);
  const order = (await orderRef.get()).data();

  if (order.seller !== req.uid) return res.status(403).send("Forbidden");

  await db.collection("users").doc(order.buyer)
    .update({ casaBalance: admin.firestore.FieldValue.increment(order.casaAmount) });

  await db.collection("users").doc(order.seller)
    .update({ lockedCasa: admin.firestore.FieldValue.increment(-order.casaAmount) });

  await orderRef.update({ status: "COMPLETED" });
  await ledger(order.seller, order.buyer, order.casaAmount, "escrow_release", orderId);

  sendSystemMessage(orderId, "Payment confirmed. CASA released.");
  res.send("Trade completed");
});

/* ================= ESCROW TIMEOUT ================= */

setInterval(async () => {
  const now = Date.now();
  const snap = await db.collection("p2p_orders").where("status", "==", "INITIATED").get();

  snap.forEach(async d => {
    const o = d.data();
    if (o.expiresAt < now) {
      await db.collection("users").doc(o.seller).update({
        casaBalance: admin.firestore.FieldValue.increment(o.casaAmount),
        lockedCasa: admin.firestore.FieldValue.increment(-o.casaAmount)
      });
      await d.ref.update({ status: "CANCELLED" });
      await ledger("system", o.seller, o.casaAmount, "escrow_refund", d.id);
      sendSystemMessage(d.id, "Escrow timeout. Funds refunded.");
    }
  });
}, 300000);

/* ================= REPORT & BAN ================= */

app.post("/p2p/report", userAuth, async (req, res) => {
  await db.collection("reports").add({
    reporter: req.uid,
    ...req.body,
    status: "pending",
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
  res.send("Report submitted");
});

app.post("/admin/ban", adminAuth, async (req, res) => {
  const { uid } = req.body;
  const userRef = db.collection("users").doc(uid);
  const user = (await userRef.get()).data();

  await ledger(uid, "system", user.casaBalance, "confiscation", uid);
  await userRef.update({ casaBalance: 0, lockedCasa: 0, banned: true });

  res.send("User banned. Contact: eluxxrevo@gmail.com");
});

/* ================= ANALYTICS ================= */

app.get("/admin/analytics", adminAuth, async (req, res) => {
  const users = await db.collection("users").get();
  const orders = await db.collection("p2p_orders").get();
  res.json({
    totalUsers: users.size,
    activeOrders: orders.docs.filter(o => o.data().status === "INITIATED").length
  });
});

/* ================= SOCKET.IO CHAT ================= */

io.use(async (socket, next) => {
  const { uid } = socket.handshake.auth;
  if (!uid) return next(new Error("Unauthorized"));

  const user = (await db.collection("users").doc(uid).get()).data();
  if (!user || user.banned) return next(new Error("Banned"));

  socket.uid = uid;
  next();
});

io.on("connection", socket => {

  socket.on("join_p2p_chat", async ({ orderId }) => {
    const order = (await db.collection("p2p_orders").doc(orderId).get()).data();
    if ([order.buyer, order.seller].includes(socket.uid)) {
      socket.join(orderId);
    }
  });

  socket.on("send_message", async ({ orderId, message, type }) => {
    const msg = {
      orderId,
      senderId: socket.uid,
      message,
      type: type || "text",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    await db.collection("p2p_messages").add(msg);
    io.to(orderId).emit("new_message", msg);
  });

  socket.on("admin_join_chat", ({ orderId }) => socket.join(orderId));
});

async function sendSystemMessage(orderId, text) {
  const msg = {
    orderId,
    senderId: "system",
    message: text,
    type: "system",
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };
  await db.collection("p2p_messages").add(msg);
  io.to(orderId).emit("new_message", msg);
}

/* ================= START ================= */

server.listen(3000, () => {
  console.log("CASA backend running on port 3000");
});
