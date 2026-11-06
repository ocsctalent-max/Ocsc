# ThaID TypeScript sample (Express)

โฟลเดอร์นี้เป็นตัวอย่างแอปแยกจาก CodeIgniter/PHP เดิม เพื่อให้ทดลอง flow ก่อนนำ service/routes ไปผสานกับเว็บหลัก โดยไม่แก้หรือแทนที่แอป PHP เดิม

## ต้องมี

- Node.js 20 ขึ้นไป
- Client ID/Client Secret และ callback URL ที่ลงทะเบียนกับ ThaID RP

## เริ่มใช้งาน

```bash
cd typescript
npm install
cp .env.example .env
```

Windows PowerShell ใช้ `Copy-Item .env.example .env` แทน `cp` แล้วกรอกค่าใน `.env` ให้ครบ โดย `THAID_REDIRECT_URI` ต้องตรงกับ callback URL ที่ลงทะเบียนไว้ เช่น `http://localhost:3000/auth/callback` สำหรับการทดสอบในเครื่อง (ใช้ได้ก็ต่อเมื่อ ThaID อนุญาต/ลงทะเบียน URL นี้)

```bash
npm run dev
```

เปิด `http://localhost:3000` จากนั้นทดสอบ login, callback, refresh, introspection, validation และ revoke

## Routes

- `GET /` หน้าเริ่มต้น
- `GET /auth/login` เริ่ม OAuth Authorization Code + PKCE
- `GET /auth/callback` รับ callback, ตรวจ state/nonce และตรวจลายเซ็น ID token
- `GET /dashboard` แสดง claims ที่ตรวจสอบแล้ว (ไม่แสดง token ลับ)
- `POST /auth/refresh` ต่ออายุ token
- `POST /auth/introspect` ตรวจ token
- `POST /auth/validate-token` ตรวจ ID token ซ้ำ
- `POST /auth/revoke` revoke และล้าง session
- `POST /auth/logout` ล้าง session

## ข้อควรทราบก่อนใช้งานจริง

- `.env` มี client secret และ session secret: ห้าม commit หรือส่งให้ browser/client; ใช้ secret manager/environment variables บน server.
- `express-session` ใช้ MemoryStore ค่าเริ่มต้นเพื่อการทดลองเท่านั้น ไม่เหมาะกับ production หรือหลาย instance; ควรติดตั้ง persistent store (เช่น Redis) และใช้ HTTPS, `NODE_ENV=production`.
- ตั้ง `SESSION_SECRET` เป็น random secret ยาวอย่างน้อย 32 ตัวอักษร และตั้ง callback URL ให้เป็น HTTPS ใน production.
- Endpoint introspection ตั้งจาก `THAID_INTROSPECT_URL`; ตัวอย่าง PHP ใน repo ส่งค่า `token` เป็น `Bearer <token>` แต่ควรยืนยันรูปแบบที่ ThaID กำหนดสำหรับ RP ของคุณก่อน.
- Revoke endpoint อ่านจาก OpenID discovery (`revocation_endpoint`). ทดสอบกับ sandbox/ระบบที่ได้รับอนุญาตก่อน.
- สิทธิ์ scope, รูปแบบ client authentication และข้อกำหนดการตรวจ claims ต้องยืนยันกับเอกสาร/ผู้ดูแล ThaID สำหรับ client ของคุณ โค้ดนี้ตรวจ issuer, audience, ลายเซ็น และ nonce ตามค่าที่ได้รับ.
- ควรเพิ่ม rate limiting, structured logging ที่ไม่บันทึก token/ข้อมูลส่วนบุคคล, monitoring และ security review ก่อน deployment.
- ฐาน session ใน Express store เป็น server-side; cookie มี HttpOnly, SameSite=Lax และเปิด Secure ใน production.

## Build

```bash
npm run build
npm start
```
