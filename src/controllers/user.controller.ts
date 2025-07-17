import { Request, Response } from "express";
import pool from "../config/db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { serialize } from "cookie";
import nodemailer from "nodemailer";
import axios from "axios";
import dotenv from "dotenv";
import { apiResponse } from "../model/response/response_standard";
import { signIn } from "../model/response/signin_interface";
import { sendSMS } from "../model/request/sendSMS";
import { contactSchema, DeleteSchema } from "../model/request/contactUse";
import { DeletegroupsSchema, groupsSchema } from "../model/request/groups";
import { any } from "zod";

dotenv.config();

export default class UserController {
  //#region Register

  async registerUser(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
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
        return res.status(200).json({
          success: false,
          message: "❌ อีเมลหรือเบอร์โทรนี้ถูกใช้ไปแล้ว",
          statusCode: 200,
        });
      }
      //เขียนโค้ดให้ดีๆหน่อย
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

      return res.status(200).json({
        success: true,
        message: "✅ สมัครสมาชิกสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ สมัครไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region LoginUser
  async loginUser(
    req: Request,
    res: Response<apiResponse<signIn>>
  ): Promise<Response<apiResponse>> {
    const { email, password } = req.body;
    try {
      const [users]: any = await pool.query(
        "SELECT * FROM users WHERE email = ? OR phone = ?",
        [email, email]
      );

      if (users.length === 0) {
        return res.status(200).json({
          success: false,
          message: "❌ ไม่พบผู้ใช้นี้",
          statusCode: 200,
        });
      }

      const user = users[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(200).json({
          success: false,
          message: "❌ รหัสผ่านไม่ถูกต้อง",
          statusCode: 200,
        });
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
      // data:{token, firstname: userData.firstname},
      return res.status(200).json({
        success: true,
        message: "✅ เข้าสู่ระบบสำเร็จ",
        data: {
          token, // ✅ เพิ่มบรรทัดนี้
          firstname: user.first_name + " " + user.last_name,
        },
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("Login error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ เกิดข้อผิดพลาด",
        statusCode: 404,
        data: error,
      });
    }
  }
  //#endregion

  //#region forgotPassword
  async forgotPassword(req: Request, res: Response<apiResponse>) {
    const { email } = req.body;
    console.log("REQ BODY:", req.body);
    if (!email) {
      return res.status(200).json({
        success: false,
        message: "⚠️ กรุณากรอกอีเมล",
        statusCode: 200,
      });
    }

    try {
      // ค้นหาผู้ใช้งานใน DB
      const [rows]: any = await pool.query(
        "SELECT id, email, first_name FROM users WHERE email = ?",
        [email]
      );
      if (rows.length === 0) {
        return res.status(200).json({
          success: false,
          message: "❌ ไม่พบผู้ใช้งานนี้",
          statusCode: 200,
        });
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

      return res.status(200).json({
        success: true,
        message:
          "✅ ส่งอีเมลสำหรับรีเซ็ตรหัสผ่านไปยังอีเมลที่ลงทะเบียนไว้แล้ว กรุณาตรวจสอบอีเมลของคุณ",
        statusCode: 200,
      });
    } catch (err: any) {
      console.error("❌ Send Mail Error:", err);
      return res
        .status(404)
        .json({ success: false, message: "เกิดข้อผิดพลาด", statusCode: 404 });
    }
  }
  //#endregion

  //#region resetPassword
  async resetPassword(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    const { userId, newPassword } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const [result]: any = await pool.query(
        "UPDATE users SET password = ? WHERE id = ?",
        [hashedPassword, userId]
      );
      if (result.affectedRows === 0) {
        return res
          .status(200)
          .json({ success: false, message: "❌ ไม่พบผู้ใช้", statusCode: 200 });
      }

      return res.status(200).json({
        success: true,
        message: "✅ รีเซ็ตรหัสผ่านสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Reset Error:", error);
      return res
        .status(404)
        .json({ success: false, message: "เกิดข้อผิดพลาด", statusCode: 404 });
    }
  }
  //#endregion

  //#region sendSMS
  async sendSMS(
    req: Request<any, any, sendSMS>,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    const {
      msisdn,
      message,
      sender,
      scheduled_delivery,
      force,
      Shorten_url,
      tracking_url,
      expire,
    } = req.body;

    try {
      const response = await axios.post(
        "https://api-v2.thaibulksms.com/sms",
        {
          msisdn,
          message,
          sender,
          scheduled_delivery,
          force,
          Shorten_url,
          tracking_url,
          expire,
        },
        {
          auth: {
            username: process.env.THAIBULKSMS_API_KEY!,
            password: process.env.THAIBULKSMS_API_SECRET!,
          },
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      console.log("response", response);

      const sql = `
      INSERT INTO sms_send
      (msisdn, message, sender, force_type, scheduled_delivery, 
      shorten_url, tracking_url, expire, api_status, api_response)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
    `;
      const toNullable = (value: any) =>
        value === "" || value === undefined ? null : value;
      //สร้างฟังก์ชั่นที่จะเปลี่ยนข้อมูลเป็น null ถ้าไม่รู้ชนิดข้อมูล

      await pool.query(sql, [
        msisdn,
        message,
        sender,
        force,
        scheduled_delivery,
        Shorten_url,
        tracking_url,
        expire,
        "success",
        JSON.stringify(response.data),
      ]);
      console.log("ข้อมูลที่บันทึกลง database", {
        msisdn,
        message,
        sender,
        scheduled_delivery,
        force,
        Shorten_url,
        tracking_url,
        expire,
      });
      return res.status(200).json({
        success: true,
        message: "success",
        statusCode: 200,
        data: response.data,
      });
    } catch (error: any) {
      console.error(
        "❌ ThaiBulkSMS Error:",
        error.response?.data || error.message
      );
      return res.status(404).json({
        success: false,
        message: "error",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region Getsms
  async contactGetSms(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    const sql = `
  SELECT 
    id,
    msisdn,
    message,
    sender,
    scheduled_delivery,
    force_type,
    Shorten_url,
    tracking_url,
    expire,
    created_at
  FROM sms_send;
`;
    try {
      const [rows] = (await pool.query(sql)) as any;

      return res.status(200).json({
        success: true,
        message: "✅ ค้นหาสำเร็จ",
        statusCode: 200,
        data: rows,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ ค้นหาไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region handleSmsWebhook
  async handleSmsWebhook(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    const {
      message_id,
      msisdn,
      status,
      sent_time,
      done_time,
      error_message,
      Transaction, // สำหรับ ThaiBulkSMS v2 (สำคัญ)
      Status,
      Time,
    } = req.query;

    console.log("📩 Webhook Callback (GET) Received:");
    console.log("Message ID:", message_id);
    console.log("Phone Number:", msisdn);
    console.log("Status:", status || Status);
    console.log("Sent Time:", sent_time);
    console.log("Done Time:", done_time);
    console.log("Error Message:", error_message);
    console.log("Transaction ID:", Transaction);
    console.log("Callback Time:", Time);

    // TODO: บันทึก log หรืออัปเดตสถานะในฐานข้อมูลได้ที่นี่

    return res.status(200).json({
      success: true,
      message: "success",
      statusCode: 200,
    });
  }
  //#endregion

  //#region contactUser
  async contactUser(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const result = contactSchema.safeParse(req.body);
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );
        console.log("result.error.errors", result.error.errors);
        return res.status(404).json({
          success: false,
          message: `${errors.join(",")}`,
          statusCode: 404,
        });
      }
      const data = result.data;

      const [emailChecking] = await pool.query(
        "SELECT id FROM contact WHERE email = ? ",
        [data.email, data.id]
      );

      if ((emailChecking as any[]).length > 0) {
        return res.status(200).json({
          success: false,
          message: "อีเมลนี้มีอยู่แล้วในระบบ",
          statusCode: 200,
        });
      }
      const [phoneChecking] = await pool.query(
        "SELECT id FROM contact WHERE phone = ? ",
        [data.phone, data.id]
      );

      if ((phoneChecking as any[]).length > 0) {
        return res.status(200).json({
          success: false,
          message: "เบอร์นี้มีอยู่แล้วในระบบ",
          statusCode: 200,
        });
      }
      const sql = `
      INSERT INTO contact
      ( first_name, last_name, phone, email, birth_date)
      VALUES (?, ?, ?, ?, ?)
    `;

      await pool.query(sql, [
        data.first_name,
        data.last_name,
        data.phone,
        data.email,
        data.birth_date,
      ]);

      return res.status(200).json({
        success: true,
        message: "✅ สมัครสมาชิกสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ สมัครไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contacGetUser
  async contactGetUser(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    const { id } = req.params;

    const sql = `
      SELECT 
        id,
        user_id,
        first_name,
        last_name,
        phone,
        email,
        birth_date,
        group_id,
        group_name,
        status,
        create_date,
        last_update
      FROM contact 
      WHERE id = ?;
    `;
    try {
      const [rows] = (await pool.query(sql, [id])) as any;

      return res.status(200).json({
        success: true,
        message: "✅ ค้นหาสำเร็จ",
        statusCode: 200,
        data: rows[0],
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ อัพเดทไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactUpdateUser
  async contactUpdateUser(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const result = contactSchema.safeParse(req.body);
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );
        console.log("result.error.errors", result.error.errors);
        return res.status(404).json({
          success: false,
          message: `${errors.join(",")}`,
          statusCode: 404,
        });
      }
      const data = result.data;
      const sql = `
      update contact set 
      user_id = ?, first_name = ?, last_name = ?, phone = ?, email = ?, 
      birth_date = ?, group_id = ?, group_name = ?, status = ?, create_date = ?,
      last_update = ?
      where id = ?;
    `;

      await pool.query(sql, [
        data.user_id,
        data.first_name,
        data.last_name,
        data.phone,
        data.email,
        data.birth_date,
        data.group_id,
        data.group_name,
        data.status,
        data.create_date,
        data.last_update,
        data.id,
      ]);

      return res.status(200).json({
        success: true,
        message: "✅ อัพเดทสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ อัพเดทไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactDelete
  async contactDelete(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const result = DeletegroupsSchema.safeParse(req.body);
      const del = result.data?.id.map(() => "?").join(",");
      const id = result.data?.id;
      const sql = `
      delete from contact where id IN (${del})
    `;
      await pool.query(sql, id);

      return res.status(200).json({
        success: true,
        message: "✅ ลบข้อมูลสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ สมัครไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactgroups
  async contactgroups(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const result = groupsSchema.safeParse(req.body);
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );
        console.log("result.error.errors", result.error.errors);
        return res.status(404).json({
          success: false,
          message: `${errors.join(",")}`,
          statusCode: 404,
        });
      }
      const data = result.data;
      const sql = `
      INSERT INTO contact_groups
      (group_name, contact_id, create_date, last_update)
      VALUES (?, ?, ?, ?)
    `;

      await pool.query(sql, [
        data.group_name,
        data.contact_id,
        data.create_date,
        data.last_update,
      ]);

      return res.status(200).json({
        success: true,
        message: "✅ สมัครสมาชิกสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ สมัครไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactGetgroups
  async contactGetgroups(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    const { id } = req.params;

    const sql = `
      SELECT 
        id,
        group_name,
        contact_id,
        create_date,
        last_update
      FROM contact_groups
      WHERE id = ?;
    `;
    try {
      const [rows] = (await pool.query(sql, [id])) as any;

      return res.status(200).json({
        success: true,
        message: "✅ ค้นหาสำเร็จ",
        statusCode: 200,
        data: rows[0],
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ ค้นหาไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactUpdategroups
  async contactUpdategroups(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const result = groupsSchema.safeParse(req.body);
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );
        console.log("result.error.errors", result.error.errors);
        return res.status(404).json({
          success: false,
          message: `${errors.join(",")}`,
          statusCode: 404,
        });
      }
      const data = result.data;
      const sql = `
      update contact_groups set 
      group_name = ?, contact_id = ?,create_date = ?, last_update = ?
      where id = ?;
    `;

      await pool.query(sql, [
        data.group_name,
        data.contact_id,
        data.create_date,
        data.last_update,
        data.id,
      ]);

      return res.status(200).json({
        success: true,
        message: "✅ อัพเดทสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ อัพเดทไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactDeletegroups
  async contactDeletegroups(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const result = DeleteSchema.safeParse(req.body);
      const del = result.data?.id.map(() => "?").join(",");
      const id = result.data?.id;
      const sql = `
      delete from contact_groups where id IN (${del})
    `;
      await pool.query(sql, id);

      return res.status(200).json({
        success: true,
        message: "✅ ลบข้อมูลสำเร็จ",
        statusCode: 200,
      });
    } catch (error: any) {
      console.error("❌ Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ สมัครไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion
}
