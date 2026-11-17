// Sentinel Audit - Reset View action
(() => {
  "use strict";

  const REFRESH_ID = "sentinel-refresh-button";

  function makeButton() {
    const button = document.createElement("button");
    button.id = REFRESH_ID;
    button.type = "button";
    button.className = "button reset-view-button";
    button.textContent = "↻ Reset view";
    button.title = "Clear this page's temporary UI state and unsaved form entries";
    button.setAttribute("aria-label", button.title);
    button.addEventListener("click", () => {
      window.dispatchEvent(new CustomEvent("sentinel:reset-view"));
    });
    return button;
  }

  function mount() {
    if (!document.body) return;
    let button = document.getElementById(REFRESH_ID);
    if (!button) button = makeButton();

    const toolbar = document.querySelector(".top-actions");
    if (toolbar) {
      button.classList.remove("reset-view-floating");
      if (button.parentElement !== toolbar) {
        toolbar.insertBefore(button, toolbar.querySelector(".icon-btn") || null);
      }
      return;
    }

    // The sign-in page has no application toolbar, so retain an accessible
    // fallback position there without covering application content.
    button.classList.add("reset-view-floating");
    if (button.parentElement !== document.body) document.body.appendChild(button);
  }

  function init() {
    mount();
    new MutationObserver(mount).observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
