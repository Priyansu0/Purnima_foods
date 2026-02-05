function toggleTheme() {
  const root = document.documentElement;
  const cur = root.getAttribute("data-theme") || "dark";
  const next = cur === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
}

(function initTheme(){
  const saved = localStorage.getItem("theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
})();

// ----------------------
// Purchases dynamic rows
// ----------------------
function addPurchaseRow(){
  const tbody = document.querySelector("#rows tbody");
  if (!tbody) return;
  const tr = document.createElement("tr");

  tr.innerHTML = `
    <td>${itemSelectHtml()}</td>
    <td class="right"><input name="qty" type="number" min="0" value="0"></td>
    <td class="right"><input name="unit_cost" type="number" step="0.01" min="0" value="0"></td>
    <td class="right"><button class="btn danger" type="button" onclick="this.closest('tr').remove()">Remove</button></td>
  `;
  tbody.appendChild(tr);
}

function addSaleRow(prefillId=null){
  const tbody = document.querySelector("#saleRows tbody");
  if (!tbody) return;
  const tr = document.createElement("tr");

  tr.innerHTML = `
    <td>${itemSelectHtml(prefillId)}</td>
    <td class="right"><input name="qty" type="number" min="0" value="1"></td>
    <td class="right"><input name="unit_price" type="number" step="0.01" min="0" value="0"></td>
    <td class="right"><button class="btn danger" type="button" onclick="this.closest('tr').remove()">Remove</button></td>
  `;
  tbody.appendChild(tr);

  // Auto-fill unit price when item changes
  const sel = tr.querySelector("select[name='item_id']");
  const priceInput = tr.querySelector("input[name='unit_price']");
  sel.addEventListener("change", () => {
    const id = parseInt(sel.value || "0", 10);
    const it = (window.ALL_ITEMS || []).find(x => x.id === id);
    if (it) priceInput.value = (it.sell_price ?? 0).toFixed(2);
  });

  if (prefillId) {
    const it = (window.ALL_ITEMS || []).find(x => x.id === prefillId);
    if (it) priceInput.value = (it.sell_price ?? 0).toFixed(2);
  }
}

// barcode scan add (USB scanner = keyboard)
function scanAdd(){
  const input = document.getElementById("scanInput");
  if (!input) return;
  const code = (input.value || "").trim();
  if (!code) return;

  const it = (window.ALL_ITEMS || []).find(x =>
    (x.barcode && x.barcode === code) || (x.sku && x.sku === code)
  );
  if (!it) {
    alert("No item found for: " + code);
    input.value = "";
    input.focus();
    return;
  }

  addSaleRow(it.id);
  input.value = "";
  input.focus();
}

function itemSelectHtml(selectedId=null){
  const items = window.ALL_ITEMS || [];
  let opts = `<option value="">-- Select --</option>`;
  for (const it of items) {
    const sel = selectedId && it.id === selectedId ? "selected" : "";
    const code = (it.sku || it.barcode) ? ` (${it.sku || it.barcode})` : "";
    opts += `<option value="${it.id}" ${sel}>${escapeHtml(it.name)}${code} [stock:${it.quantity}]</option>`;
  }
  return `<select name="item_id" required>${opts}</select>`;
}

function escapeHtml(s){
  return String(s)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

// ----------------------
// Offline Charts (Canvas)
// ----------------------
function drawBarChart(canvasId, labels, values) {
  const c = document.getElementById(canvasId);
  if (!c) return;

  const ctx = c.getContext("2d");
  const dpr = window.devicePixelRatio || 1;

  const cssW = c.clientWidth || 600;
  const cssH = c.clientHeight || 260;

  c.width = Math.floor(cssW * dpr);
  c.height = Math.floor(cssH * dpr);

  const W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);

  const styles = getComputedStyle(document.documentElement);
  const text = styles.getPropertyValue("--text").trim() || "#e7eefc";
  const muted = styles.getPropertyValue("--muted").trim() || "#9bb0d0";
  const border = styles.getPropertyValue("--border").trim() || "#1f2f4a";
  const primary = styles.getPropertyValue("--primary").trim() || "#4f7cff";

  const padL = 70 * dpr, padR = 20 * dpr, padT = 20 * dpr, padB = 60 * dpr;
  const max = Math.max(...values, 1);
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  // Axes
  ctx.strokeStyle = border;
  ctx.lineWidth = 2 * dpr;
  ctx.beginPath();
  ctx.moveTo(padL, padT);
  ctx.lineTo(padL, padT + chartH);
  ctx.lineTo(padL + chartW, padT + chartH);
  ctx.stroke();

  // Grid + y labels
  ctx.fillStyle = muted;
  ctx.font = `${12 * dpr}px sans-serif`;
  const steps = 4;
  for (let i = 0; i <= steps; i++) {
    const y = padT + chartH - (chartH * i / steps);
    const v = (max * i / steps);

    ctx.strokeStyle = border;
    ctx.lineWidth = 1 * dpr;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + chartW, y);
    ctx.stroke();

    ctx.fillText(v.toFixed(0), 10 * dpr, y + 4 * dpr);
  }

  // Bars
  const n = values.length || 1;
  const gap = Math.max(8 * dpr, chartW * 0.02);
  const barW = (chartW - gap * (n + 1)) / n;

  ctx.fillStyle = primary;
  for (let i = 0; i < n; i++) {
    const x = padL + gap + i * (barW + gap);
    const barH = (values[i] / max) * chartH;
    const y = padT + chartH - barH;

    ctx.fillRect(x, y, barW, barH);

    // labels (rotated)
    ctx.save();
    ctx.translate(x + barW / 2, padT + chartH + 10 * dpr);
    ctx.rotate(-Math.PI / 5);
    ctx.fillStyle = text;
    ctx.font = `${12 * dpr}px sans-serif`;
    ctx.fillText(String(labels[i]).slice(0, 12), -20 * dpr, 18 * dpr);
    ctx.restore();
    ctx.fillStyle = primary;
  }
}
