// Filtering for the keyguard HTML report. The page is fully readable without
// JavaScript; this only hides and shows findings that are already rendered.
(function () {
  "use strict";
  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  if (!findings.length) return;

  var chips = Array.prototype.slice.call(document.querySelectorAll(".chip"));
  var rule = document.getElementById("rule-filter");
  var search = document.getElementById("search");
  var status = document.getElementById("status");
  var emptyMsg = document.getElementById("empty-filter");
  var toggle = document.getElementById("toggle-all");
  // The toolbar ships hidden so no-JS viewers don't see controls that do nothing.
  document.getElementById("toolbar").hidden = false;

  function plural(n) { return n === 1 ? " finding" : " findings"; }

  function visible() { return findings.filter(function (f) { return !f.hidden; }); }

  // Label reflects what the button will do next, even after manual expand/collapse.
  function syncToggle() {
    var v = visible();
    var allOpen = v.length > 0 && v.every(function (f) { return f.open; });
    toggle.textContent = allOpen ? "Collapse all" : "Expand all";
    toggle.disabled = v.length === 0;
  }

  function apply() {
    var sevs = {};
    chips.forEach(function (c) { sevs[c.dataset.sev] = c.getAttribute("aria-pressed") === "true"; });
    var r = rule.value;
    var q = search.value.trim().toLowerCase();
    var shown = 0;
    findings.forEach(function (f) {
      var ok = sevs[f.dataset.sev] && (!r || f.dataset.rule === r) && (!q || f.dataset.text.indexOf(q) !== -1);
      f.hidden = !ok;
      if (ok) shown++;
    });
    document.querySelectorAll(".group").forEach(function (g) {
      g.hidden = !g.querySelector(".finding:not([hidden])");
    });
    emptyMsg.hidden = shown !== 0;
    status.textContent = shown === findings.length
      ? "Showing all " + shown + plural(shown)
      : "Showing " + shown + " of " + findings.length + plural(findings.length);
    syncToggle();
  }

  chips.forEach(function (c) {
    c.addEventListener("click", function () {
      c.setAttribute("aria-pressed", c.getAttribute("aria-pressed") === "true" ? "false" : "true");
      apply();
    });
  });
  rule.addEventListener("change", apply);
  search.addEventListener("input", apply);

  toggle.addEventListener("click", function () {
    var open = toggle.textContent === "Expand all";
    visible().forEach(function (f) { f.open = open; });
    syncToggle();
  });
  // "toggle" fires asynchronously and doesn't bubble, so listen per finding.
  findings.forEach(function (f) { f.addEventListener("toggle", syncToggle); });

  // Open the first high-severity finding so the most urgent fix is visible immediately.
  var first = document.querySelector('.finding[data-sev="high"]');
  if (first) first.open = true;
  apply();
})();
