# คู่มือสำหรับ Independent Reviewer (OmniSec Staging Deployment)

ขอบคุณที่สละเวลามาช่วยเป็น **Independent Reviewer** ให้กับระบบความปลอดภัย OmniSec ครับ!
หน้าที่ของคุณคือช่วยตรวจสอบความถูกต้องของคำขอ Deploy ขึ้นระบบทดสอบ (Staging) เพื่อป้องกันการ Deploy โดยพลการ หรือความผิดพลาดที่อาจเกิดขึ้น

---

## สรุปหน้าที่ของคุณ:
1. เมื่อมีคำขอ Deploy คุณจะได้รับอีเมล/การแจ้งเตือนจาก GitHub
2. เข้ามาตรวจ Checklist 5 ข้อ ในหน้า GitHub Actions
3. กดปุ่ม **Approve** (หรือ **Reject** หากพบสิ่งผิดปกติ)
*(ใช้เวลาไม่เกิน 2 นาทีต่อครั้ง และคุณไม่ต้องยุ่งเกี่ยวกับเซิร์ฟเวอร์หรือรหัสผ่านใดๆ เลยครับ)*

---

## ตาราง Checklist 5 ข้อที่ต้องตรวจสอบก่อนกด Approve

| ข้อที่ต้องตรวจ | สัญญาณที่ถูกต้อง (ผ่าน ✅) | สัญญาณอันตราย (ต้อง Reject ❌) |
| :--- | :--- | :--- |
| **1. Source identity** | Source SHA 40 ตัว, source-state hash และ manifest hash ตรงกับ candidate evidence | ค่าใดขาด, ย่อ, หรือมาจาก tag/branch ลอยๆ |
| **2. Publish workflow** | Workflow SHA 40 ตัวและ candidate มาจาก `staging-publish.yml@main` | Workflow/ref/event อื่น หรือไม่ทราบ workflow SHA |
| **3. Backend image** | เป็น full ref `ghcr.io/hkteerawat/omnisec-backend@sha256:...` | เป็น tag เช่น `latest` หรือ repository อื่น |
| **4. Frontend image** | เป็น full ref `ghcr.io/hkteerawat/omnisec-frontend@sha256:...` | เป็น tag หรือ repository อื่น |
| **5. Pre-approval verification** | Job `pre-approval-verification` ผ่าน และ traffic contract ถูก fix เป็น 0% โดยไม่มี input ให้เปลี่ยน | Job ล้ม, ถูก skip, เป็น rerun หรือมี traffic input |

---

## ขั้นตอนการกด Approve / Reject (วิธีใช้งาน)

1. คลิกที่ลิงก์ในอีเมลแจ้งเตือน หรือเข้ามาที่หน้า GitHub Actions ของ Repository นี้
2. สังเกตที่กล่อง **"Waiting for review"** แล้วคลิกปุ่ม **`Review deployments`**
3. หน้าต่าง Modal จะเด้งขึ้นมา:
   - ตรวจดูค่า Inputs ว่าตรงตาม Checklist 5 ข้อด้านบน
   - ติ๊กถูกที่กล่องเลือก **`staging`**
4. **การตัดสินใจ:**
   - หากข้อมูลถูกต้องทั้งหมด: คลิกปุ่มสีเขียว **`Approve and deploy`**
   - หากพบสิ่งผิดปกติ หรือไม่แน่ใจ: คลิกปุ่ม **`Reject`** พร้อมพิมพ์เหตุผลสั้นๆ

หลังอนุมัติ workflow จะอ่าน approval history เพื่อตรวจว่าผู้อนุมัติไม่ใช่ผู้เริ่ม run แล้วบันทึกเพียงผล `independentReviewerVerified=true` ลง authorization; ชื่อหรือ ID ของ reviewer จะไม่ถูกคัดลอกลง artifact แต่ approval history ของ public repository ยังคงเป็น public GitHub metadata

---

## กรณีฉุกเฉิน (Emergency Rollback Request)
หากได้รับการแจ้งเตือนว่าระบบมีปัญหา หรือเกิดเหตุฉุกเฉิน:
- หาก Workflow กำลังรอ Review อยู่ ให้คลิก **`Reject`** ทันที เพื่อระงับการทำงาน
- การ Reject ของคุณจะทำให้ระบบล็อกตัวเองทันที (Fail-Closed) และไม่กระทบต่อระบบใดๆ ครับ
