// ==UserScript==
// @name         OTP Desk - Amazon.ca autofill
// @namespace    otp-desk
// @version      1.0
// @description  After "Copy & open Amazon.ca" on OTP Desk, fills that client's email and PIN on the Amazon hiring login, then stops.
// @match        {{ site }}/*
// @match        https://hiring.amazon.ca/*
// @match        https://auth.hiring.amazon.com/*
// @grant        GM.setValue
// @grant        GM.getValue
// @grant        GM.deleteValue
// @run-at       document-idle
// @downloadURL  {{ site }}/otpdesk.user.js
// @updateURL    {{ site }}/otpdesk.user.js
// ==/UserScript==

(function () {
  "use strict";

  const SITE = "{{ site }}";
  const KEY = "pending-login";
  // The email + PIN are only kept briefly, and only for the next login.
  const MAX_AGE_MS = 3 * 60 * 1000;
  const WATCH_MS = 90 * 1000;

  // --- On OTP Desk: remember which client's login was just started. ---
  if (location.origin === SITE) {
    document.documentElement.dataset.otpAutofill = "1";
    document.addEventListener(
      "click",
      (event) => {
        const link = event.target.closest(".start-login");
        if (!link) return;
        const client = link.closest(".account");
        GM.setValue(KEY, JSON.stringify({
          email: client.dataset.email,
          pin: client.dataset.pin || "",
          at: Date.now(),
        }));
      },
      true
    );
    return;
  }

  // --- On Amazon: fill the email, press Continue, then fill the PIN and stop. ---
  // React ignores plain `input.value = ...`, so use the native setter and fire events.
  function typeInto(input, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    input.focus();
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function visible(el) {
    return el.offsetParent !== null && !el.disabled && !el.readOnly;
  }

  function findEmailInput() {
    const el = document.querySelector('#login, [data-test-id="input-test-id-login"]');
    return el && visible(el) ? el : null;
  }

  // The PIN page could use one box or one box per digit.
  function findPinInputs() {
    const inputs = [...document.querySelectorAll("input")].filter(
      (i) => visible(i) && i.type !== "hidden" && i.id !== "login"
    );
    const digitBoxes = inputs.filter((i) => i.maxLength === 1);
    if (digitBoxes.length >= 4) return digitBoxes;
    const single = inputs.find((i) => {
      const hints = [i.type, i.id, i.name, i.getAttribute("aria-label"),
        i.getAttribute("data-test-id"), i.autocomplete].join(" ");
      return i.type === "password" || /pin/i.test(hints);
    });
    return single ? [single] : [];
  }

  function fillPin(inputs, pin) {
    if (inputs.length === 1) typeInto(inputs[0], pin);
    else inputs.forEach((box, i) => typeInto(box, pin[i] || ""));
  }

  async function run() {
    let pending;
    try {
      pending = JSON.parse(await GM.getValue(KEY, "null"));
    } catch (e) {
      pending = null;
    }
    if (!pending || Date.now() - pending.at > MAX_AGE_MS) return;

    let emailDone = false;
    const started = Date.now();
    const timer = setInterval(async () => {
      if (Date.now() - started > WATCH_MS) {
        clearInterval(timer);
        await GM.deleteValue(KEY);
        return;
      }

      if (!emailDone) {
        const email = findEmailInput();
        if (!email) return;
        typeInto(email, pending.email);
        emailDone = true;
        if (!pending.pin) {
          clearInterval(timer);
          await GM.deleteValue(KEY);
        }
        setTimeout(() => {
          const next = document.querySelector('[data-test-id="button-continue"]');
          if (next) next.click();
        }, 400);
        return;
      }

      const pinInputs = findPinInputs();
      if (!pinInputs.length) return;
      fillPin(pinInputs, pending.pin);
      // Stop here: the person reviews and continues, then enters the OTP.
      clearInterval(timer);
      await GM.deleteValue(KEY);
    }, 300);
  }

  run();
})();
