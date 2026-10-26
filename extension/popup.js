// The toolbar popup: what the phone sent (each acted on only at a click here), and sending to the phone.
import { MAX_FILE, label } from "./handoff.js";

const $ = (id) => document.getElementById(id);
const send = (m) => chrome.runtime.sendMessage(m);
const say = (t, bad = false) => { $("said").textContent = t; $("said").className = bad ? "problem" : "muted"; };

function button(text, primary, onclick) {
  const b = Object.assign(document.createElement("button"), { textContent: text, className: primary ? "primary" : "text" });
  b.onclick = onclick;
  return b;
}

async function render() {
  const r = await send({ t: "inbox" });
  $("unpaired").hidden = !!r?.paired;
  $("send").hidden = !r?.paired;
  const items = r?.items || [];
  $("empty").hidden = items.length > 0;
  $("items").replaceChildren(...items.map((it) => {
    const row = Object.assign(document.createElement("div"), { className: "item" });
    row.append(Object.assign(document.createElement("span"), { textContent: label(it), title: it.type === "link" ? it.url : it.type === "text" ? it.text : it.file.name }));
    if (it.type === "link") {
      row.append(button("Open", true, async () => { await send({ t: "openLink", id: it.id }); render(); }));
      row.append(button("Copy", false, async () => { await navigator.clipboard.writeText(it.url); await send({ t: "dismiss", id: it.id }); render(); }));
    } else if (it.type === "text") {
      row.append(button("Copy", true, async () => { await navigator.clipboard.writeText(it.text); await send({ t: "dismiss", id: it.id }); render(); }));
    } else {
      row.append(button("Download", true, async (e) => {
        e.target.disabled = true; e.target.textContent = "Getting it…";
        const f = await send({ t: "file", id: it.id });
        if (!f?.ok) { e.target.textContent = f?.why || "Failed"; return; }
        const bytes = Uint8Array.from(atob(f.data), (c) => c.charCodeAt(0));
        const url = URL.createObjectURL(new Blob([bytes], { type: f.mime }));
        await chrome.downloads.download({ url, filename: f.name, saveAs: false, conflictAction: "uniquify" });
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        render();
      }));
    }
    row.append(button("×", false, async () => { await send({ t: "dismiss", id: it.id }); render(); }));
    return row;
  }));
}

$("continue").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const r = await send({ t: "sendLink", url: tab?.url || "", open: true });
  say(r?.ok ? "Sent: the phone shows it to open." : `Not sent: ${r?.why || "no answer"}`, !r?.ok);
};
$("sendNote").onclick = async () => {
  const text = $("note").value;
  if (!text.trim()) return;
  const r = await send({ t: "sendText", text });
  if (r?.ok) $("note").value = "";
  say(r?.ok ? "Sent." : `Not sent: ${r?.why || "no answer"}`, !r?.ok);
};
$("pick").onclick = () => $("file").click();
$("file").onchange = async () => {
  const f = $("file").files[0];
  $("file").value = "";
  if (!f) return;
  if (f.size > MAX_FILE) { say(`Too big: at most ${MAX_FILE / 1024 / 1024} MB.`, true); return; }
  say(`Sending ${f.name}…`);
  const u8 = new Uint8Array(await f.arrayBuffer());
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  const r = await send({ t: "sendFile", name: f.name, mime: f.type, data: btoa(s) });
  say(r?.ok ? `Sent ${f.name}: it saves to Download/Sphinx on the phone.` : `Not sent: ${r?.why || "no answer"}`, !r?.ok);
};
render();
