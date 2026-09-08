# คู่มือการตั้งค่า Public Control Repository

เอกสารนี้เป็น checklist สำหรับการตั้งค่าในอนาคตเท่านั้น การมีไฟล์เหล่านี้ไม่ได้แปลว่า repository, package access หรือ staging host พร้อมใช้งานแล้ว

---

### ขั้นตอนที่ 1: สร้าง Repository ใหม่บน GitHub
1. ไปที่ https://github.com/new
2. ตั้งชื่อ Repository ให้ตรงกับ trust contract: `HKTeerawat/omnisec-staging-control`
3. เลือกสถานะเป็น **Public** (จำเป็น เพื่อใช้ Environment Reviewer ฟรี)
4. ห้าม push จนกว่า static/unit checks ผ่านและมี authorization แยกสำหรับการสร้าง public repository

---

### ขั้นตอนที่ 2: ตั้งค่า Environment "staging"
1. ในหน้า Repository เข้าไปที่ **Settings** → **Environments**
2. คลิก **New environment** แล้วตั้งชื่อว่า `staging`
3. ในหัวข้อ **Deployment protection rules**:
   - ติ๊กถูกที่ **Required reviewers**
   - พิมพ์ GitHub Username ของเพื่อน แล้วคลิกเพิ่ม
   - ติ๊กถูกที่ **Prevent self-review** (ห้ามผู้เริ่ม workflow กด Approve เอง)
   - ปิดการ bypass protection rules สำหรับ administrator
4. ในหัวข้อ **Deployment branches**:
   - เลือก **Selected branches** → เพิ่มกฎ `main` (อนุญาตเฉพาะ main)

---

### ขั้นตอนที่ 3: ตั้งค่า Branch Protection สำหรับ branch "main"
1. ไปที่ **Settings** → **Branches**
2. คลิก **Add branch protection rule** ที่ branch `main`
3. ติ๊กถูกที่:
   - **Require a pull request before merging** พร้อม approval อย่างน้อย 1 คน
   - **Dismiss stale approvals** เมื่อมี commit ใหม่
   - **Require status checks to pass before merging** (เลือก `control-ci / static-security-and-schema`)
   - ปิด force push และ branch deletion
   - **Do not allow bypassing the above settings**

---

### ขั้นตอนที่ 4: ให้ workflow อ่าน private GHCR packages แบบแคบ
1. ที่ package `omnisec-backend` และ `omnisec-frontend` ให้เพิ่ม repository `HKTeerawat/omnisec-staging-control` ใน **Manage Actions access** ด้วยสิทธิ์ Read เท่านั้น
2. ห้ามเปลี่ยน package visibility เป็น public เพื่อหลบขั้นตอนนี้
3. Workflow ใช้เฉพาะ `GITHUB_TOKEN` แบบชั่วคราวพร้อม `packages: read`; ห้ามเพิ่ม PAT, signing key หรือ repository secret
4. หาก policy นี้ตั้งไม่ได้หรืออ่าน package ไม่ได้ ให้ถือว่า authorization workflow เป็น `blocked`

### ขั้นตอนที่ 5: ตรวจ external settings ก่อนใช้งาน
- ยืนยัน repository เป็น public และ default branch คือ `main`
- ยืนยัน required reviewer เป็นบุคคลอื่นจริงและมีอย่างน้อย Read access
- ยืนยัน prevent-self-review, no-admin-bypass และ selected branch `main`
- ยืนยัน Actions policy อนุญาตเฉพาะ actions ที่ pin ด้วย commit SHA ใน source
- เก็บผลตรวจเป็น control-plane evidence; ห้าม dispatch เพียงเพราะไฟล์ถูก push แล้ว
