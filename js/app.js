(function () {
  "use strict";
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function el(tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // Audience tabs
  $$(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$(".tabs button").forEach(function (x) { x.setAttribute("aria-selected", String(x === b)); });
      $$(".tabpanel").forEach(function (p) { p.hidden = p.getAttribute("data-panel") !== b.getAttribute("data-tab"); });
    });
  });

  // Step-through demos
  var DEMOS = {
    block: {
      end: "bad",
      stages: [["Request", "Delete customer records"], ["Oracle", "Recommends: allow"], ["PATIENCE Core", "No matching policy"], ["Blocked", "POLICY_UNKNOWN"]],
      notes: [
        "An agent asks to delete a batch of customer records (synthetic).",
        "The Oracle recommends allowing it. A recommendation alone never executes anything.",
        "Core checks its deterministic rules and finds no policy covering this action.",
        "Unknown policy fails closed: the action is blocked and logged with reason code POLICY_UNKNOWN. (Example code; structured reason codes are planned.)"
      ]
    },
    approve: {
      end: "ok",
      stages: [["Request", "Refund [AMOUNT]"], ["PATIENCE Core", "Needs human approval"], ["Approver", "approver-A approves"], ["Executor", "Allowlisted refund runs"], ["Receipt", "RCPT-0042"]],
      notes: [
        "An agent requests a refund above the threshold.",
        "Core marks it consequential and pauses it for a person.",
        "A human approves this one decision. Note: approver identity is not verified yet in the prototype.",
        "Only an action on the allowlist can run.",
        "A receipt records who approved, which rule applied, and when, then joins the audit chain."
      ],
      receipt: "RECEIPT RCPT-0042\naction:    refund (allowlisted)\nrule:      R-04 refunds over threshold\napproved:  approver-A (identity not verified yet)\ntime:      2026-10-28T09:03:56Z\ntenant:    demo-sandbox (synthetic)"
    }
  };

  $$(".demo[data-demo]").forEach(function (root) {
    var cfg = DEMOS[root.getAttribute("data-demo")];
    var wrap = $(".stages", root), note = $(".note", root), rc = $(".receipt", root);
    var prog = el("div", "progress", "<i></i>"); wrap.parentNode.insertBefore(prog, wrap.nextSibling);
    var nodes = cfg.stages.map(function (s, i) {
      var n = el("div", "stage" + (i === cfg.stages.length - 1 ? " end-" + cfg.end : ""), "<b>" + esc(s[0]) + "</b><span>" + esc(s[1]) + "</span>");
      wrap.appendChild(n); return n;
    });
    var step = 0, timer = null, N = nodes.length;
    var play = $(".play", root), back = $(".back", root), next = $(".next", root);
    function render() {
      nodes.forEach(function (n, i) { n.classList.toggle("on", i <= step); n.classList.toggle("cur", i === step); });
      note.textContent = "Step " + (step + 1) + " of " + N + ": " + cfg.notes[step];
      prog.firstChild.style.width = ((step + 1) / N * 100) + "%";
      back.disabled = step === 0; next.disabled = step >= N - 1;
      play.textContent = timer ? "Playing…" : (step >= N - 1 ? "Replay" : "Play");
      if (rc) { rc.hidden = step < N - 1; rc.textContent = cfg.receipt; }
    }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }
    play.addEventListener("click", function () {
      if (timer) return;
      if (step >= N - 1) step = 0;
      timer = setInterval(function () { if (step >= N - 1) { stop(); render(); return; } step++; render(); }, reduced ? 1800 : 1200);
      render();
    });
    back.addEventListener("click", function () { stop(); step = Math.max(0, step - 1); render(); });
    next.addEventListener("click", function () { stop(); step = Math.min(N - 1, step + 1); render(); });
    render();
  });

  // Hash chain with real SHA-256
  var CHAIN = [
    "genesis",
    "approval: refund approved by approver-A",
    "executed: refund RCPT-0042",
    "blocked: delete-records POLICY_UNKNOWN",
    "executed: invoice reminder RCPT-0043",
    "denied: vendor payment by approver-B"
  ];
  var hasCrypto = !!(window.crypto && window.crypto.subtle);
  function sha256(s) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    });
  }
  var stored = null, count = 2, tamper = false, chainTimer = null;
  var chainEl = $("#chain-demo .chain"), chainNote = $("#chain-note");
  function buildStored() {
    var out = [], prev = "0".repeat(64), p = Promise.resolve();
    CHAIN.forEach(function (d) { p = p.then(function () { return sha256(prev + "|" + d).then(function (h) { out.push({ prev: prev, hash: h }); prev = h; }); }); });
    return p.then(function () { stored = out; });
  }
  function renderChain() {
    var items = CHAIN.slice(0, count), broken = false, p = Promise.resolve(), res = [];
    items.forEach(function (d, i) {
      var data = tamper && i === 1 ? d.replace("approved", "denied") : d;
      p = p.then(function () { return sha256(stored[i].prev + "|" + data).then(function (h) { if (h !== stored[i].hash) broken = true; res.push({ data: data, prev: stored[i].prev, hash: h, bad: broken }); }); });
    });
    return p.then(function () {
      chainEl.innerHTML = "";
      res.forEach(function (b, i) {
        chainEl.appendChild(el("div", "blk" + (b.bad ? " broken" : ""),
          "<b>Block " + (i + 1) + "</b><div class='d'>" + esc(b.data) + "</div><div class='h'>prev " + b.prev.slice(0, 16) + "…</div><div class='h'>hash " + b.hash.slice(0, 16) + "…</div><div class='v'>" + (b.bad ? "✕ link broken" : "✓ verified") + "</div>"));
      });
      chainNote.textContent = broken
        ? "Block 2 was edited after it was written. Its SHA-256 no longer matches the stored hash, so it and every later block fail verification."
        : "Each block stores the previous block's SHA-256 hash, computed live in your browser.";
      $("#chain-add").disabled = count >= CHAIN.length;
    });
  }
  if (hasCrypto) {
    buildStored().then(renderChain);
    $("#chain-add").addEventListener("click", function () { if (count < CHAIN.length) { count++; renderChain(); } });
    $("#chain-reset").addEventListener("click", function () { clearInterval(chainTimer); chainTimer = null; count = 2; tamper = false; $("#chain-tamper").checked = false; renderChain(); });
    $("#chain-tamper").addEventListener("change", function (e) { tamper = e.target.checked; renderChain(); });
    $("#chain-play").addEventListener("click", function () {
      clearInterval(chainTimer); count = 1; renderChain();
      chainTimer = setInterval(function () { if (count >= CHAIN.length) { clearInterval(chainTimer); chainTimer = null; return; } count++; renderChain(); }, reduced ? 1200 : 700);
    });
  } else {
    chainNote.textContent = "This browser does not expose Web Crypto here (it needs HTTPS or localhost).";
  }

  // Simulated live feed + developer section
  var feedList = $("#feed-list"), filters = $("#feed-filters"), filter = "all", events = [], idx = 0;
  function cls(t) { return t === "policy.failed_closed" ? "bad" : (t === "action.executed" ? "ok" : ""); }
  function detail(e) { return esc(e.summary || [e.result, e.rule, e.reason_code, e.receipt].filter(Boolean).join(" · ")) + " <span class='t'>(" + esc(e.workflow) + ", " + esc(e.actor) + ")</span>"; }
  function push(e) {
    if (filter !== "all" && e.type !== filter) return;
    var now = new Date();
    var li = el("li", null, "<span class='t'>" + now.toTimeString().slice(0, 8) + "</span><span class='ty " + cls(e.type) + "'>" + esc(e.type) + "</span><span>" + detail(e) + "</span>");
    feedList.insertBefore(li, feedList.firstChild);
    while (feedList.children.length > 8) feedList.removeChild(feedList.lastChild);
  }
  fetch("data/demo_events.json").then(function (r) { return r.json(); }).then(function (d) {
    events = d.events;
    $("#sample").textContent = JSON.stringify(events[4], null, 2);
    var types = ["all"].concat(events.map(function (e) { return e.type; }).filter(function (t, i, a) { return a.indexOf(t) === i; }));
    types.forEach(function (t) {
      var b = el("button", t === "all" ? "sel" : "", esc(t)); b.addEventListener("click", function () {
        filter = t; $$("button", filters).forEach(function (x) { x.classList.toggle("sel", x === b); }); feedList.innerHTML = "";
      }); filters.appendChild(b);
    });
    for (var k = 0; k < 4; k++) push(events[idx++]);
    setInterval(function () { push(events[idx % events.length]); idx++; }, reduced ? 4000 : 2200);
  }).catch(function () { feedList.innerHTML = "<li>Feed data could not load. Serve the site over HTTP.</li>"; });
  fetch("data/event.schema.json").then(function (r) { return r.text(); }).then(function (t) { $("#schema").textContent = t; }).catch(function () {});
})();
