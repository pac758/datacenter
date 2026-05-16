# datacenter (ระบบศูนย์กลางข้อมูลโรงเรียน)

โปรเจกต์นี้เป็น Google Apps Script Web App ที่ใช้ Google Sheets เป็นฐานข้อมูล และใช้ Google Drive สำหรับเก็บไฟล์แนบ

## รูปแบบการนำไปใช้กับโรงเรียนอื่น

- แบบที่แนะนำ: **Self-host ต่อโรงเรียน**
  - โรงเรียนแต่ละแห่งมี Apps Script / Spreadsheet / Drive Folder ของตัวเอง
  - ข้อดี: แยกข้อมูลชัดเจน, ดูแลง่าย, ไม่ต้องทำ multi-tenant
- แบบศูนย์กลาง (SaaS / หลายโรงเรียนในชุดเดียว)
  - ใช้สคริปต์ชุดเดียว แล้วแยกข้อมูลด้วย “schoolCode → spreadsheetId/folderId”
  - ข้อดี: อัปเดตครั้งเดียวทุกโรงเรียน, ทำ dashboard รวมได้
  - ต้องพัฒนาเพิ่ม: ระบบเลือกโรงเรียน, แยกสิทธิ์/ข้อมูล, งาน onboarding

## Quick Start (Self-host ต่อโรงเรียน)

### 1) เตรียมทรัพยากรของโรงเรียน

- สร้าง Google Sheet 1 ไฟล์ (จะเป็นชีตตอบ Google Form หรือชีตเก็บข้อมูลเอกสาร)
  - ชื่อชีตเริ่มต้นที่ระบบใช้: `การตอบแบบฟอร์ม 1`
- เตรียมโฟลเดอร์ใน Google Drive 1 โฟลเดอร์ (ใช้เก็บไฟล์แนบ)
  - ถ้าไม่ระบุ Folder ID ระบบจะสร้างโฟลเดอร์ใหม่ให้อัตโนมัติใน Drive ของผู้ Deploy

### 2) สร้าง Apps Script และ Deploy เป็น Web App

มี 2 วิธี

**วิธี A: ผ่านหน้า Apps Script (ง่ายสุด)**
- สร้างโปรเจกต์ใหม่ที่ https://script.google.com/
- นำไฟล์ใน repo นี้ไปวาง (ไฟล์ `.js` และ `.html`)
- Deploy → New deployment → Select type: Web app
- Execute as: `Me` (หรือค่าตามนโยบายโรงเรียน)
- Who has access:
  - แนะนำ: `Anyone` หรือ `Anyone within <domain>` (ถ้าเป็น Google Workspace)
  - ถ้าต้องการให้เปิดได้แบบไม่ต้องล็อกอิน: `Anyone` (anonymous) ตามที่ตั้งไว้ใน manifest

**วิธี B: ใช้ clasp (เหมาะสำหรับทีม/อัปเดตด้วย Git)**
- ติดตั้ง clasp และล็อกอิน
  - `npm i -g @google/clasp`
  - `clasp login`
- สร้าง Apps Script ใหม่ แล้วค่อย `clasp push`
  - หมายเหตุ: ใน repo นี้มี `.clasp.json` ที่อ้างอิง `scriptId` ของเครื่องผู้พัฒนาเดิม ให้แก้เป็นของโรงเรียนตัวเอง

### 3) ตั้งค่าครั้งแรก (ผ่านหน้า Admin)

- เปิด Web App ที่ Deploy แล้ว
- ระบบจะพาไปที่หน้าตั้งค่า (Admin) ถ้ายังไม่ตั้งค่า `Spreadsheet ID`
- เข้าหน้า Admin ด้วยรหัสเริ่มต้น: `3333`
- ตั้งค่าอย่างน้อย:
  - Spreadsheet ID
  - ชื่อชีต (เช่น `การตอบแบบฟอร์ม 1`)
  - Folder ID (ถ้ามี)
- กดบันทึก แล้วรีโหลดหน้า

## ข้อควรคำนึงตอนส่งต่อให้โรงเรียนอื่น

- ตั้งค่าโรงเรียนเก็บไว้ในชีต `setup` ภายใน Spreadsheet ที่ระบุไว้ (ดู [รหัส.js](file:///d:/datacenter/รหัส.js))
- ระบบสร้าง token secret อัตโนมัติใน Script Properties (`TOKEN_SECRET`)
- แนะนำให้โรงเรียนเปลี่ยนรหัสผู้ดูแลหลังติดตั้ง (เมนู “เครื่องมือ” → “เปลี่ยนรหัสผู้ดูแลระบบ”)

## โครงสร้างไฟล์สำคัญ

- [appsscript.json](file:///d:/datacenter/appsscript.json) ตั้งค่า webapp/scopes
- [รหัส.js](file:///d:/datacenter/รหัส.js) ฝั่ง server + config + upload
- [index.html](file:///d:/datacenter/index.html) หน้าเว็บหลัก (include ไฟล์ย่อย)
- [AdminPanel.html](file:///d:/datacenter/AdminPanel.html) หน้าตั้งค่า/เครื่องมือผู้ดูแล

