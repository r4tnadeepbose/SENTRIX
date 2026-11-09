const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const form = document.getElementById("form");
const error = document.getElementById("error");
const submit = document.getElementById("submit");
document.getElementById("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("sx.theme", next); } catch (e) {}
});
document.getElementById("eye").addEventListener("click", () => {
  const pw = document.getElementById("password");
  pw.type = pw.type === "password" ? "text" : "password";
  document.getElementById("eye").setAttribute("aria-label", pw.type === "password" ? "Show password" : "Hide password");
});
async function signIn(username, password, remember) {
  error.hidden = true;
  submit.disabled = true;
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, remember: !!remember }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Sign-in failed.");
    if (data.token) { try { sessionStorage.setItem("sx.token", data.token); } catch (e) {} }
    location.href = "/";
  } catch (err) {
    error.textContent = err.message;
    error.hidden = false;
    submit.disabled = false;
  }
}
form.addEventListener("submit", (e) => {
  e.preventDefault();
  signIn(document.getElementById("username").value.trim(),
         document.getElementById("password").value,
         document.getElementById("remember").checked);
});
fetch("/api/auth/demo-info").then((r) => r.json()).then((info) => {
  if (!info.enabled || !info.accounts || !info.accounts.length) return;
  document.getElementById("roster").hidden = false;
  document.getElementById("roster-rows").innerHTML = info.accounts.map((a, i) => `
    <div class="demo-row">
      <div class="dwho">
        <div style="font-size:12.5px;font-weight:600">${esc(a.username)} <span class="chip neutral" style="margin-left:4px">${esc(String(a.role).replace(/_/g, " "))}</span></div>
        <div style="font-size:11px;color:var(--dim)">${esc(a.title || "")}</div>
        <div class="mono" style="font-size:10.5px;color:var(--faint);margin-top:2px">${esc(a.username)} / ${esc(a.password)}</div>
      </div>
      <button class="btn sm" type="button" data-acct="${i}">Sign in</button>
    </div>`).join("");
  document.querySelectorAll("[data-acct]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const a = info.accounts[+btn.dataset.acct];
      document.getElementById("username").value = a.username;
      document.getElementById("password").value = a.password;
      signIn(a.username, a.password, false);
    });
  });
}).catch(() => {});
