"use strict";

// Educational UI only. Production authorization belongs in the receiving tool,
// using the SDK's cryptographic verification and a trusted usage backend.
const scenarios = {
  allowed: { action: "tool:draft_proforma", callsUsed: 0 },
  "wrong-tool": { action: "tool:submit_purchase_order", callsUsed: 0 },
  replay: { action: "tool:draft_proforma", callsUsed: 1 },
};
const illustrativeGrant = {
  audience: "tool:draft_proforma",
  capabilities: ["tool:draft_proforma"],
  maxCalls: 1,
};

function illustrateAuthorization(request, grant) {
  if (request.action !== grant.audience)
    return {
      decision: "denied",
      title: "Outside the granted scope",
      code: "AUDIENCE_MISMATCH",
      description:
        "A draft permission cannot authorize submitting a purchase order. The request is rejected.",
      checks: ["Audience mismatch", "Tool does not execute"],
    };
  if (!grant.capabilities.includes(request.action))
    return {
      decision: "denied",
      title: "Capability not granted",
      code: "CAPABILITY_VIOLATION",
      description:
        "The requested capability is absent from the grant. The tool does not execute.",
      checks: ["Capability missing", "Tool does not execute"],
    };
  if (request.callsUsed >= grant.maxCalls)
    return {
      decision: "denied",
      title: "This token has already been used",
      code: "CONSTRAINT_VIOLATION",
      description:
        "The token permits one call. Replaying it exceeds the allowance, even before it expires.",
      checks: ["Audience matched", "Call allowance exhausted"],
    };
  return {
    decision: "allowed",
    title: "Permission granted",
    code: "ALLOWED",
    description: "The audience and capability match. One call is available.",
    checks: ["Audience matched", "Capability granted", "Within call limit"],
  };
}

document.querySelectorAll("[data-scenario]").forEach((button) => {
  button.addEventListener("click", () => {
    const request = scenarios[button.dataset.scenario];
    const result = illustrateAuthorization(request, illustrativeGrant);
    document.querySelectorAll("[data-scenario]").forEach((item) => {
      const selected = item === button;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    document.getElementById("requested-action").textContent = request.action;
    document.getElementById("decision-panel").dataset.decision =
      result.decision;
    document.getElementById("decision-title").textContent = result.title;
    document.getElementById("decision-code").textContent = result.code;
    document.getElementById("decision-description").textContent =
      result.description;
    const checks = document.getElementById("decision-checks");
    checks.replaceChildren(
      ...result.checks.map((text) => {
        const span = document.createElement("span");
        span.textContent = text;
        return span;
      }),
    );
  });
});

const languageTabs = [...document.querySelectorAll("[data-language]")];
function selectLanguage(tab, focus = false) {
  languageTabs.forEach((item) => {
    const selected = item === tab;
    item.setAttribute("aria-selected", String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute("aria-controls")).hidden =
      !selected;
  });
  document.querySelector(".code-copy").dataset.copy =
    `example-${tab.dataset.language}`;
  if (focus) tab.focus();
}
languageTabs.forEach((tab, index) => {
  tab.addEventListener("click", () => selectLanguage(tab));
  tab.addEventListener("keydown", (event) => {
    const moves = {
      ArrowRight: (index + 1) % languageTabs.length,
      ArrowLeft: (index + languageTabs.length - 1) % languageTabs.length,
      Home: 0,
      End: languageTabs.length - 1,
    };
    if (Object.hasOwn(moves, event.key)) {
      event.preventDefault();
      selectLanguage(languageTabs[moves[event.key]], true);
    }
  });
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copy);
    const label = button.textContent;
    let copied = false;
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(target.textContent);
        copied = true;
      }
    } catch {
      /* The browser may require the legacy user-gesture path. */
    }
    if (!copied) {
      const temporary = document.createElement("textarea");
      temporary.value = target.textContent;
      temporary.setAttribute("readonly", "");
      temporary.style.cssText = "position:fixed;left:-9999px;top:0;";
      document.body.append(temporary);
      temporary.select();
      try {
        copied = document.execCommand("copy");
      } catch {
        copied = false;
      }
      temporary.remove();
      button.focus({ preventScroll: true });
    }
    if (copied) {
      button.textContent = "Copied";
      document.getElementById("copy-status").textContent =
        "Copied to clipboard.";
      window.setTimeout(() => {
        button.textContent = label;
      }, 1800);
    } else {
      const range = document.createRange();
      range.selectNodeContents(target);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      document.getElementById("copy-status").textContent =
        "Text selected. Use your device's copy action.";
    }
  });
});
