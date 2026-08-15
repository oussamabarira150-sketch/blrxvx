# VIRTUS - رفع على Oracle Cloud Free Tier
### دليل خطوة بخطوة (10 دقائق)

نظام التنفيذ: Ubuntu 22.04/24.04 — كل الأوامر أدناه تُنفذ على خادمك.

---

## 1) إنشاء الحساب والـ VM
1. ادخل https://signup.cloud.oracle.com - اختر Free Tier (بطاقة بنكية للتحقق فقط، لا يُخصم)
2. اختر منطقة (Region) قريبة منك وصديقك مثل: Germany Central (Frankfurt) أو South Africa North (Johannesburg)
3. Create a VM Instance:
   - **Image**: Ubuntu 22.04 (Minimal) أو 24.04
   - **Shape**: Ampere A1 (Flex 4 OCPU / 24GB) — إن ظهر "out of capacity" اختر VM.Standard.E2.1.Micro
   - **SSH key**: أنشئ keyPair واحفظ الملف الخاص (id_rsa) — ستحتاجه للدخول
4. انتظر حتى يصبح Running وسجّل **Public IP**

---

## 2) فتح المنفذ 13480 (Security List)
1. في الـ VM الخاص بك: `Virtual Cloud Network` → السير الفرعي `Subnet` → `Security List` → Default
2. `Add Ingress Rules`:
   - Source CIDR: `0.0.0.0/0`
   - IP Protocol: `TCP`
   - Destination Port Range: `13480`

---

## 3) الدخول ورفع الحزمة
من جهازك (PowerShell/الطرفية في مجلد الحزمة):
```bash
ssh -i id_rsa ubuntu@IP_السيرفر
# بعد الدخول — رفع الملفات من جهازك:
scp -i id_rsa -r files server.js README.md ubuntu@IP_السيرفر:~/
```
(بديل: `sftp` أو رفع من الويب عبر Cloud Shell Console)

---

## 4) تثبيت Node والتشغيل
```bash
# على السيرفر:
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
cd ~
node server.js
```
**اختبار فوري** (من السيرفر): `curl http://127.0.0.1:13480/api/update` → يجب أن يظهر JSON.
**اختبار من جوالك** (شبكة بيانات): `http://IP_السيرفر:13480/api/update` → نفس JSON = الخادم عالمي.

---

## 5) الإبقاء شغالاً للأبد (pm2)
```bash
sudo npm install -g pm2
pm2 start server.js --name virtus
pm2 save
pm2 startup    # اتبع التعليمات الناتجة (نسخة-paste أمر systemd)
```
الآن يبقى حياً ويعيد التشغيل تلقائياً بعد أي Reboot.

---

## 6) تجهيز نسخة الصديق
- عدّل `Virtus_Settings.json` في جهاز صديقك:
```json
{
  "Virtus_IP": "IP_السيرفر",
  "port": 13480,
  "url_virtus": "http://IP_السيرفر:13480",
  "url_inject": "http://IP_السيرفر:13480/api/inject",
  "url_bypass": "http://IP_السيرفر:13480/api/bypass"
}
```
- أرسل لصديقك: `cracked.exe` + `Virtus_Settings.json`

---

## ملاحظات
- هذا الـ server.js معدّل مسبقاً: يرد على كل عميل بنفس العنوان الذي اتصل به (أنت محلياً لو شئت + صديقك عالمياً)
- HWID صديقك يُسجل تلقائياً بحالة active في hwids.json
- لتأمين المنفذ من الغرباء لاحقاً: أضف فحص token في handleAuth