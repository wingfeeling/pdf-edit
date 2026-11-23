/* 編輯器的進階功能檢查：登入 → 向後端扣試用次數（付費會員不扣） */
(function () {
  const NAMES = { ocr: '掃描檔文字辨識', convert: 'Word／Excel／PPT 轉檔' };
  window.PDFAPP = {
    async gate(feature) {
      await App.ready;
      if (!App.user) {
        if (!confirm(`「${NAMES[feature] || feature}」是進階功能，用 Google 帳號登入後每個月可以免費使用幾次。\n要現在登入嗎？`)) return false;
        try { await App.signIn(); } catch (e) { return false; }
        if (!App.user) return false; paintWho();
      }
      try {
        const r = await App.api('/api/usage/consume', { body: { feature } });
        if (!r.paid && r.remaining != null && r.remaining <= 3 && window.toast) setTimeout(() => toast(`「${NAMES[feature]}」這個月的免費次數還剩 ${r.remaining} 次`, 5000), 2500);
        return true;
      } catch (e) {
        if (e.status === 402) { if (confirm(e.message + '\n\n要打開「方案與價格」頁面嗎？')) window.open('pricing.html', '_blank'); return false; }
        throw e;
      }
    }
  };
  function paintWho() {
    const el = document.getElementById('edWho'); if (!el) return; const u = App.user;
    el.innerHTML = u ? `<a href="account.html" target="_blank" title="${App.esc(u.email)}" style="font-size:12.5px;color:#374151;text-decoration:none;white-space:nowrap">👤 ${App.esc(u.displayName || u.email)}</a>`
      : `<button class="btn sm" id="edLogin">登入</button>`;
    const b = document.getElementById('edLogin'); if (b) b.onclick = () => App.signIn().then(paintWho).catch(() => { });
  }
  App.ready.then(paintWho); App.onAuth(paintWho);
})();
