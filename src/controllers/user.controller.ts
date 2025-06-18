import { Request, Response } from "express";
import pool from "../config/db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { serialize } from "cookie";

// registerUser
export const registerUser = async (req: Request, res: Response) => {
  const {
    first_name,
    last_name,
    phone,
    email,
    password,
    product,
    newsletter,
    accept_terms,
    accept_policy,
  } = req.body;

  try {
    // ตรวจสอบว่ามี email หรือ phone ซ้ำไหม
    const [exists]: any = await pool.query(
      "SELECT id FROM users WHERE email = ? OR phone = ?",
      [email, phone]
    );

    if (exists.length > 0) {
      return res
        .status(400)
        .json({ message: "❌ อีเมลหรือเบอร์โทรนี้ถูกใช้ไปแล้ว" });
    }

    // เข้ารหัสรหัสผ่านก่อนเก็บ
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users
      (first_name, last_name, phone, email, password, product, newsletter, accept_terms, accept_policy)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await pool.query(sql, [
      first_name,
      last_name,
      phone,
      email,
      hashedPassword,
      product,
      newsletter || false,
      accept_terms || false,
      accept_policy || false,
    ]);

    res.status(201).json({ message: "✅ สมัครสมาชิกสำเร็จ" });
  } catch (error: any) {
    console.error("❌ Error:", error);
    res
      .status(500)
      .json({ message: "❌ สมัครไม่สำเร็จ", error: error.message });
  }
};

//loginUser
export const loginUser = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const [users]: any = await pool.query(
      "SELECT * FROM users WHERE email = ? OR phone = ?",
      [email, email]
    );

    if (users.length === 0) {
      return res.status(400).json({ message: "❌ ไม่พบผู้ใช้นี้" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "❌ รหัสผ่านไม่ถูกต้อง" });
    }

    // ✅ สร้าง token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    // ✅ ส่ง token เป็น cookie httpOnly
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Set-Cookie",
      serialize("token", token, {
        httpOnly: true, // ป้องกัน JS ฝั่ง frontend อ่าน cookie
        path: "/", // ใช้ได้ทุก path
        sameSite: "lax", // ป้องกัน CSRF เบื้องต้น
        secure: process.env.NODE_ENV === "production", // ใช้เฉพาะ HTTPS ตอน production
        maxAge: 60 * 60 * 24,
      })
    );

    res.status(200).json({
      message: "✅ เข้าสู่ระบบสำเร็จ",
      token, // ✅ เพิ่มบรรทัดนี้
    });
  } catch (error: any) {
    console.error("Login error:", error);
    res
      .status(500)
      .json({ message: "❌ เกิดข้อผิดพลาด", error: error.message });
  }
};
