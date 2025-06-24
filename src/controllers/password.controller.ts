import nodemailer from "nodemailer";
import { Request, Response } from "express";
import pool from "../config/db";
import bcrypt from "bcrypt";

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  console.log("REQ BODY:", req.body);
  if (!email) {
    return res.status(400).json({ message: "⚠️ กรุณากรอกอีเมล" });
  }

  try {
    // ค้นหาผู้ใช้งานใน DB
    const [rows]: any = await pool.query(
      "SELECT id, email, first_name FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "❌ ไม่พบผู้ใช้งานนี้" });
    }

    const user = rows[0];

    // 🔐 สร้างลิงก์สำหรับรีเซ็ตรหัสผ่าน (ในระบบจริงควรมี token ด้วย)
    const resetLink = `http://localhost:3000/reset-password?user=${user.id}`;

    // ✉️ สร้าง transporter ส่งเมลผ่าน Gmail
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // 📨 ส่งอีเมล
    await transporter.sendMail({
      from: `"MBT Support" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "รีเซ็ตรหัสผ่านของคุณ",
      html: `
        <p>สวัสดีคุณ ${user.first_name},</p>
        <p>เราได้รับคำขอรีเซ็ตรหัสผ่านของคุณ</p>
        <p>คลิก <a href="${resetLink}">ที่นี่</a> เพื่อรีเซ็ตรหัสผ่านของคุณ</p>
        <p>หากคุณไม่ได้ร้องขอ กรุณาเพิกเฉยอีเมลนี้</p>
        <br />
        <p>ขอบคุณค่ะ<br/>MBT Support</p>
      `,
    });

    return res.json({
      message:
        "✅ ส่งอีเมลสำหรับรีเซ็ตรหัสผ่านไปยังอีเมลที่ลงทะเบียนไว้แล้ว กรุณาตรวจสอบอีเมลของคุณ",
    });
  } catch (err: any) {
    console.error("❌ Send Mail Error:", err);
    return res
      .status(500)
      .json({ message: "เกิดข้อผิดพลาด", error: err.message });
  }
};
