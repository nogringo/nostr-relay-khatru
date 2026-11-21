"use strict";

const relayURL = new URL("../", location.href).href;
const $ = (selector, root = document) => root.querySelector(selector);
const panelOf = (name) => $(`[data-panel="${name}"]`);
const HEX64 = /^[0-9a-f]{64}$/i;

const loaded = new Set();
let savedInfo = { name: "", description: "", icon: "" };

// NIP-19 bech32

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GENERATOR[i];
  }
  return chk;
}

function hrpExpand(hrp) {
  const codes = [...hrp].map((c) => c.charCodeAt(0));
  return [...codes.map((c) => c >>> 5), 0, ...codes.map((c) => c & 31)];
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  const maxAcc = (1 << (from + to - 1)) - 1;
  for (const v of data) {
    acc = ((acc << from) | v) & maxAcc;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new Error("invalid bech32 padding");
  }
  return out;
}

function bech32Decode(text) {
  const s = text.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (sep < 1 || sep + 7 > s.length) throw new Error("not bech32");
  const hrp = s.slice(0, sep);
  const data = [...s.slice(sep + 1)].map((c) => {
    const v = CHARSET.indexOf(c);
    if (v === -1) throw new Error("not bech32");
    return v;
  });
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error("bad bech32 checksum");
  return { hrp, bytes: convertBits(data.slice(0, -6), 5, 8, false) };
}

function bech32Encode(hrp, bytes) {
  const data = convertBits(bytes, 8, 5, true);
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...checksum].map((v) => CHARSET[v]).join("");
}

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => hex.match(/../g).map((h) => parseInt(h, 16));
const npubEncode = (hex) => bech32Encode("npub", fromHex(hex));

function tlvValue(bytes, type) {
  for (let i = 0; i + 1 < bytes.length; i += 2 + bytes[i + 1]) {
    if (bytes[i] === type && bytes[i + 1] === 32) return toHex(bytes.slice(i + 2, i + 34));
  }
  throw new Error(`no type ${type} entry`);
}

function decodeEntity(input, plain, tlv) {
  const value = input.trim().replace(/^nostr:/i, "");
  if (HEX64.test(value)) return value.toLowerCase();
  const { hrp, bytes } = bech32Decode(value);
  if (hrp === plain && bytes.length === 32) return toHex(bytes);
  if (hrp === tlv) return tlvValue(bytes, 0);
  throw new Error(`unexpected ${hrp}`);
}

function parsePubkey(input) {
  try {
    return decodeEntity(input, "npub", "nprofile");
  } catch {
    throw new Error("Enter an npub, an nprofile or a 64-character hex pubkey.");
  }
}

function parseEventId(input) {
  try {
    return decodeEntity(input, "note", "nevent");
  } catch {
    throw new Error("Enter a nevent, a note or a 64-character hex event id.");
  }
}

function parseKind(input) {
  const value = input.trim();
  if (!/^\d+$/.test(value) || Number(value) > 65535) {
    throw new Error("Enter a kind number between 0 and 65535.");
  }
  return Number(value);
}

// NIP-86 calls, authorized with a NIP-98 event

async function sha256Hex(text) {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

function base64(text) {
  let binary = "";
  for (const b of new TextEncoder().encode(text)) binary += String.fromCharCode(b);
  return btoa(binary);
}

async function httpAuth(url, body) {
  const tags = [["u", url], ["method", "POST"]];
  if (body) tags.push(["payload", await sha256Hex(body)]);
  const auth = await window.nostr.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    content: "",
    tags,
  });
  return "Nostr " + base64(JSON.stringify(auth));
}

async function call(method, params = []) {
  const body = JSON.stringify({ method, params });
  const response = await fetch(relayURL, {
    method: "POST",
    headers: {
      "Content-Type": "application/nostr+json+rpc",
      Authorization: await httpAuth(relayURL, body),
    },
    body,
  });
  const reply = await response.json();
  if (reply.error) throw new Error(reply.error);
  return reply.result;
}

function describe(error) {
  const message = error?.message || String(error);
  if (message.includes("auth event is too old")) return "The signature took too long to arrive. Try again.";
  return message.charAt(0).toUpperCase() + message.slice(1);
}

function showError(panel, message) {
  const el = $("[data-error]", panel);
  el.textContent = message;
  el.hidden = !message;
}

async function run(panel, button, task) {
  showError(panel, "");
  if (button) button.disabled = true;
  try {
    await task();
    return true;
  } catch (error) {
    showError(panel, describe(error));
    return false;
  } finally {
    if (button) button.disabled = false;
  }
}

// Overview

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} d ${hours} h`;
  if (hours > 0) return `${hours} h ${minutes} min`;
  return `${minutes} min`;
}

function renderStats({ result: stats }) {
  const panel = panelOf("overview");
  const set = (key, value) => ($(`[data-stat="${key}"]`, panel).textContent = value);
  set("events", stats.events.toLocaleString());
  set("connections", stats.connections.toLocaleString());
  set("subscriptions", stats.subscriptions.toLocaleString());
  set("uptime", formatDuration(Math.max(0, Date.now() / 1000 - stats.started_at)));
  set("version", stats.version);
}

// Ban lists

const lists = {
  pubkeys: {
    list: "listbannedpubkeys",
    add: "banpubkey",
    remove: "unbanpubkey",
    removeLabel: "Unban",
    key: (entry) => entry.pubkey,
    show: npubEncode,
    parse: parsePubkey,
    confirm: (hex) => `Ban ${npubEncode(hex)} and delete everything it published on this relay? Deleted events cannot be restored.`,
  },
  events: {
    list: "listbannedevents",
    add: "banevent",
    remove: "allowevent",
    removeLabel: "Unban",
    key: (entry) => entry.id,
    show: (hex) => hex,
    parse: parseEventId,
    confirm: () => "Delete this event from the relay and refuse it from now on? It cannot be restored.",
  },
  ips: {
    list: "listblockedips",
    add: "blockip",
    remove: "unblockip",
    removeLabel: "Unblock",
    key: (entry) => entry.ip,
    show: (ip) => ip,
    parse: (input) => input.trim(),
  },
  kinds: {
    list: "listdisallowedkinds",
    add: "disallowkind",
    remove: "allowkind",
    removeLabel: "Accept again",
    key: (kind) => kind,
    show: (kind) => `Kind ${kind}`,
    parse: parseKind,
    withoutReason: true,
  },
};

function renderList(name, entries) {
  const cfg = lists[name];
  const panel = panelOf(name);
  const items = entries.map((entry) => {
    const value = cfg.key(entry);
    const item = document.createElement("li");
    const text = document.createElement("div");
    text.className = "entry-text";

    const label = document.createElement("span");
    label.className = cfg.withoutReason ? "" : "mono clip";
    label.textContent = cfg.show(value);
    label.title = label.textContent;
    text.append(label);

    if (entry.reason) {
      const reason = document.createElement("span");
      reason.className = "reason";
      reason.textContent = entry.reason;
      text.append(reason);
    }
    item.append(text);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "quiet";
    button.textContent = cfg.removeLabel;
    button.addEventListener("click", async () => {
      if (await run(panel, button, () => call(cfg.remove, [value]))) loadPanel(name, true);
    });
    item.append(button);
    return item;
  });
  $("[data-list]", panel).replaceChildren(...items);
  $("[data-empty]", panel).hidden = entries.length > 0;
}

for (const [name, cfg] of Object.entries(lists)) {
  const panel = panelOf(name);
  const form = $("[data-form]", panel);
  form.addEventListener("input", () => showError(panel, ""));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    let value;
    try {
      value = cfg.parse(form.elements.entry.value);
    } catch (error) {
      showError(panel, error.message);
      return;
    }
    if (cfg.confirm && !window.confirm(cfg.confirm(value))) return;
    const params = cfg.withoutReason ? [value] : [value, form.elements.reason.value.trim()];
    if (await run(panel, $("button", form), () => call(cfg.add, params))) {
      form.reset();
      loadPanel(name, true);
    }
  });
}

// Relay info

const infoForm = $("[data-info-form]");
const infoMethods = { name: "changerelayname", description: "changerelaydescription", icon: "changerelayicon" };

function infoChanges() {
  return Object.keys(infoMethods).filter((field) => infoForm.elements[field].value !== savedInfo[field]);
}

function showRelay(doc) {
  $("#relay-name").textContent = doc.name || "Relay admin";
  document.title = doc.name ? `${doc.name} admin` : "Relay admin";
}

async function loadInfo() {
  const response = await fetch(relayURL, { headers: { Accept: "application/nostr+json" } });
  const doc = await response.json();
  savedInfo = { name: doc.name ?? "", description: doc.description ?? "", icon: doc.icon ?? "" };
  for (const field of Object.keys(infoMethods)) infoForm.elements[field].value = savedInfo[field];
  $("button", infoForm).disabled = true;
  showRelay(doc);
}

infoForm.addEventListener("input", () => {
  $("button", infoForm).disabled = infoChanges().length === 0;
});

infoForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("button", infoForm);
  await run(panelOf("info"), button, async () => {
    for (const field of infoChanges()) {
      const value = infoForm.elements[field].value.trim();
      await call(infoMethods[field], [value]);
      savedInfo[field] = value;
      infoForm.elements[field].value = value;
    }
    showRelay(savedInfo);
  });
  button.disabled = infoChanges().length === 0;
});

// Backup

const backupButton = $("[data-backup]");
const backupForm = $("[data-backup-form]");
const backupFrame = $("[data-backup-frame]");

// a fetch would hold the whole zip in memory: the browser's own download writes it to disk
async function downloadBackup() {
  backupForm.elements.authorization.value = await httpAuth(backupForm.action);
  backupForm.submit();
}

// the zip downloads without loading the frame, so a page in it is the relay's error
backupFrame.addEventListener("load", () => {
  const message = backupFrame.contentDocument?.body?.textContent.trim();
  if (message) showError(panelOf("backup"), describe(new Error(message)));
});

backupButton.addEventListener("click", () => run(panelOf("backup"), backupButton, downloadBackup));

// Navigation

async function loadPanel(name, force = false) {
  if (name === "backup" || (!force && loaded.has(name))) return;
  const panel = panelOf(name);
  await run(panel, $("[data-refresh]", panel), async () => {
    if (name === "overview") renderStats(await call("stats"));
    else if (name === "info") await loadInfo();
    else renderList(name, await call(lists[name].list));
    loaded.add(name);
  });
}

function openTab(name) {
  for (const tab of document.querySelectorAll("[data-tab]")) {
    if (tab.dataset.tab === name) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  for (const panel of document.querySelectorAll("[data-panel]")) panel.hidden = panel.dataset.panel !== name;
  loadPanel(name);
}

for (const tab of document.querySelectorAll("[data-tab]")) {
  tab.addEventListener("click", () => openTab(tab.dataset.tab));
}

for (const panel of document.querySelectorAll("[data-panel]")) {
  $("[data-refresh]", panel)?.addEventListener("click", () => loadPanel(panel.dataset.panel, true));
}

// Session

async function signIn() {
  const button = $("#sign-in-button");
  const error = $("#sign-in-error");
  const fail = (message) => {
    error.textContent = message;
    error.hidden = false;
  };
  error.hidden = true;

  if (!window.nostr) return fail("No Nostr extension found. Install one, such as Alby or nos2x, then reload this page.");
  if (!window.crypto?.subtle) return fail("Open this page over HTTPS: browsers only hash requests on secure pages.");

  button.disabled = true;
  try {
    const pubkey = await window.nostr.getPublicKey();
    const stats = await call("stats");
    $("#admin-npub").textContent = npubEncode(pubkey);
    $("#admin-npub").title = npubEncode(pubkey);
    renderStats(stats);
    loaded.add("overview");
    $("#sign-in").hidden = true;
    $("#session").hidden = false;
    $("#console").hidden = false;
  } catch (err) {
    const message = describe(err);
    fail(message.includes("not an admin")
      ? "This key is not an admin of this relay. Add its npub to ADMIN_PUBKEYS, then restart the relay."
      : message);
  } finally {
    button.disabled = false;
  }
}

$("#sign-in-button").addEventListener("click", signIn);
$("#sign-out").addEventListener("click", () => location.reload());

$("#relay-url").textContent = relayURL.replace(/^http/, "ws").replace(/\/$/, "");
loadPanel("info");
