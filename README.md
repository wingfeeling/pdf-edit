# PDF 線上編輯器

網頁和後端放在同一個 Cloudflare Worker，檔案放在 GitHub。
Cloudflare 連結這個 repo 後，**在 GitHub 改檔案 → Commit → 1～2 分鐘後網站自動更新**，自己的電腦不用裝 Node 或任何東西。

**第一次上架請看 `上架教學.html`**（一步一步，含帳號要不要跟 ar-pet 分開的說明）。
價格、試用次數、成本請看 `定價與成本試算.html`。

## 檔案說明

```
wrangler.toml       ← 要改：Firebase 專案 ID、D1 資料庫 ID、價格、試用次數（改完 Commit 就自動部署）
web/                網頁
  index.html        首頁
  editor.html       PDF 編輯器（改字、加字＋選字體、簽名、印章、轉正、拆分、轉檔）
  admin.html        批次線上簽名管理頁：上傳報名表、匯出「姓名・Email・簽名網址」名單、退回重簽、下載已簽檔
  sign.html         學生簽名頁（要用名單上的 Email 登入才打得開）
  pricing.html      方案與購買
  account.html      我的帳號、試用次數、購買紀錄
  ops.html          網站用量監控、學校匯款手動開通（只有 SITE_ADMINS 看得到）
  privacy.html      隱私權政策範本
  terms.html        服務條款與退款政策範本
  js/config.js      ← 要改：Firebase 網頁設定
worker/
  src/index.js      後端程式（資料表會自動建立）
  schema.sql        資料表結構（參考用，不用手動執行）
```

## 祕密（在 Cloudflare 主控台設定，不要放 GitHub）

Workers 和 Pages → pdf-editor → 設定 → 變數和祕密，類型選「祕密」：

- `SITE_ADMINS`：可以看用量監控頁的 Gmail
- `ECPAY_HASH_KEY`、`ECPAY_HASH_IV`：綠界金鑰

## 這一版的變更

- 編輯器加字、改字時可以選字體：12 種內建字體（思源黑體、思源宋體、霞鶩文楷、芫荽、粉圓等，每台電腦都一樣）、自動偵測電腦裡的常見字體（標楷體、微軟正黑體、新細明體、蘋方等）；Chrome／Edge 可以讀取電腦裡的全部字體，其他瀏覽器可以輸入字體名稱。匯出 PDF 時照畫面上的字體畫進去，對方沒有這個字體也看得到。
- 拿掉群發信件（不再需要 Resend／Brevo）。管理頁改成「姓名・Email・簽名網址」名單，可以複製貼到 Excel／Google 試算表，或下載 CSV，自己用學校信箱、LINE 發出。學生要用名單上的 Email 登入才打得開。
- 改成 GitHub 自動部署：網頁和後端合成一個 Worker，不用 Node、不用 Cloudflare Pages、不用手動建資料表。

## 安全與個資

- 學生要用名單上的 Google 帳號登入才看得到自己的文件，網址被別人點到也打不開。
- 簽名網址是 32 個字的亂碼，猜不到。
- 回傳後由後端鎖定，只有承辦人按「退回重簽」才會解鎖。
- 每個批次都有保存期限，到期自動刪除全部檔案。
- 編輯器的檔案都在使用者的瀏覽器裡處理，不會上傳。
- `DEV_AUTH` 必須維持 `"off"`。
