// reset.controller.ts
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import pool from "../config/db"; // path อาจต้องเปลี่ยนให้ตรงของคุณ

export const resetPassword = async (req: Request, res: Response) => {
  const { userId, newPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const [result]: any = await pool.query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedPassword, userId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "❌ ไม่พบผู้ใช้" });
    }

    res.status(200).json({ message: "✅ รีเซ็ตรหัสผ่านสำเร็จ" });
  } catch (error: any) {
    console.error("❌ Reset Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาด", error: error.message });
  }
};
