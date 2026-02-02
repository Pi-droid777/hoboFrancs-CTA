async function loadLedger() {
  const res = await fetch("./ledger.json", { cache: "no-store" });
  if (!res.ok) throw new Error("Ledger not found.");
  return res.json();
}

document.getElementById("btn").addEventListener("click", async () => {
  const out = document.getElementById("out");
  out.textContent = "Checking ledger...";
  const hash = document.getElementById("hash").value.trim();

  if (!hash) { out.textContent = "Paste a sha256 hash first."; return; }

  try {
    const ledger = await loadLedger();
    const match = (ledger.records || []).find(r => r.cert?.file_hash === hash);

    if (!match) { out.textContent = "No match found in public ledger."; return; }

    out.textContent =
      `✅ Match found\n\n` +
      `Ledger ID: #${match.ledger_id}\n` +
      `Recorded at: ${match.recorded_at}\n` +
      `File: ${match.cert.file}\n` +
      `File hash: ${match.cert.file_hash}\n` +
      `Creator timestamp: ${match.cert.timestamp}\n` +
      `Tier: ${match.cert.tier}\n` +
      `Git commit: ${match.cert.git_commit || "n/a"}\n`;
  } catch (e) {
    out.textContent = "Error: " + e.message;
  }
});
