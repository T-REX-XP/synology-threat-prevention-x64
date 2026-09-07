import "../styles/app.css";
import { $ } from "./util.js";
import { loadOverview } from "./overview.js";
import { bindEvents, loadEvents } from "./events.js";
import { bindPolicy, loadPolicy } from "./policy.js";
import { loadStats } from "./statistics.js";
import { bindSettings, loadSettings } from "./settings.js";

function setTab(name) {
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.classList.toggle("on", b.getAttribute("data-tab") === name);
  });
  ["overview", "events", "policy", "statistics", "settings"].forEach(function (t) {
    $(t).classList.toggle("hidden", t !== name);
  });
  if (name === "overview") loadOverview();
  if (name === "events") loadEvents();
  if (name === "policy") loadPolicy();
  if (name === "statistics") loadStats();
  if (name === "settings") loadSettings();
}

document.querySelectorAll(".tabs button").forEach(function (b) {
  b.addEventListener("click", function () { setTab(b.getAttribute("data-tab")); });
});
bindEvents();
bindPolicy();
bindSettings();
setTab("overview");
