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
import {
  DeletegroupsSchema,
  groupsSchema,
  addExistingContactsToGroupSchema,
} from "../model/request/groups";
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
    console.log(req.body);
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
          users_id: user.id,
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
    console.log("contactUse", req.body);
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
      ( user_id,first_name, last_name, phone, email, birth_date)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

      await pool.query(sql, [
        data.user_id,
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
    const { group_id } = req.query;
    console.log("📥 contactGetUser called with group_id:", group_id);

    let sql = `
      SELECT DISTINCT
        c.id,
        c.user_id,
        c.first_name,
        c.last_name,
        c.phone,
        c.email,
        c.birth_date,
        cg.groups_id as group_id,
        g.group_name,
        c.status,
        c.create_date,
        c.last_update
      FROM contact c
    `;

    const queryParams: any[] = [];

    // ถ้ามี group_id ให้ JOIN กับตาราง count_groups และ contact_groups
    if (group_id) {
      sql += `
        INNER JOIN count_groups cg ON c.id = cg.contact_id
        INNER JOIN contact_groups g ON cg.groups_id = g.id
        WHERE cg.groups_id = ?
      `;
      queryParams.push(group_id);
      console.log("🔍 Using INNER JOIN for group_id:", group_id);
    } else {
      // ถ้าไม่มี group_id ให้แสดงทั้งหมด (LEFT JOIN เพื่อแสดงข้อมูลที่ไม่อยู่ในกลุ่มด้วย)
      sql += `
        LEFT JOIN count_groups cg ON c.id = cg.contact_id
        LEFT JOIN contact_groups g ON cg.groups_id = g.id
      `;
      console.log("🔍 Using LEFT JOIN for all contacts");
    }

    sql += ` ORDER BY c.create_date DESC`;
    console.log("📝 Final SQL:", sql);
    console.log("📋 Query params:", queryParams);

    try {
      const [rows] = (await pool.query(sql, queryParams)) as any;
      console.log("📊 Query result rows:", rows);
      console.log("📊 Number of rows found:", rows.length);

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
        message: "❌ ดึงข้อมูลไม่สำเร็จ",
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
      console.log("📥 Received contactUpdateUser request:", req.body);
      const result = contactSchema.safeParse(req.body);
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );

        console.log("❌ Validation errors:", result.error.errors);
        return res.status(404).json({
          success: false,
          message: `Validation failed: ${errors.join(", ")}`,
          statusCode: 404,
        });
      }

      const data = result.data;
      console.log("🔄 Updating contact with data:", data);

      // 🚀 ใช้ Transaction เพื่อความปลอดภัย
      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // 1️⃣ อัปเดต contact table
        const updateContactSql = `
          UPDATE contact SET 
          user_id = ?, first_name = ?, last_name = ?, phone = ?, email = ?, 
          birth_date = ?, group_id = ?, group_name = ?, status = ?, create_date = ?,
          last_update = ?
          WHERE id = ?;
        `;

        await connection.query(updateContactSql, [
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

        // 2️⃣ จัดการ group relationships
        console.log("🔍 Processing group relationships...");
        console.log("📋 data.group_ids:", data.group_ids);
        console.log("📋 data.group_id:", data.group_id);

        // ✅ เฉพาะเมื่อมีการส่ง group_ids หรือ group_id มาใหม่ เท่านั้นจึงจะอัปเดต relationships
        if (
          (data.group_ids &&
            Array.isArray(data.group_ids) &&
            data.group_ids.length > 0) ||
          data.group_id
        ) {
          // ลบ entries เก่าใน count_groups สำหรับ contact นี้
          const deleteOldGroupsSql = `
            DELETE FROM count_groups WHERE contact_id = ?;
          `;
          await connection.query(deleteOldGroupsSql, [data.id]);
          console.log(
            `🗑️ Deleted old group relationships for contact ${data.id}`
          );

          // เพิ่ม entries ใหม่ใน count_groups (รองรับหลายกลุ่ม)
          if (
            data.group_ids &&
            Array.isArray(data.group_ids) &&
            data.group_ids.length > 0
          ) {
            // ✅ รองรับหลายกลุ่มผ่าน group_ids array
            const insertNewGroupSql = `
              INSERT INTO count_groups (groups_id, contact_id) 
              VALUES (?, ?);
            `;

            for (const groupId of data.group_ids) {
              await connection.query(insertNewGroupSql, [groupId, data.id]);
              console.log(
                `✅ Added group relationship: contact ${data.id} -> group ${groupId}`
              );
            }

            console.log(`🎯 Total groups added: ${data.group_ids.length}`);
          } else if (data.group_id) {
            // 🔄 รองรับ backward compatibility กับ group_id เดียว
            const insertNewGroupSql = `
              INSERT INTO count_groups (groups_id, contact_id) 
              VALUES (?, ?);
            `;
            await connection.query(insertNewGroupSql, [data.group_id, data.id]);
            console.log(
              `✅ Added single group relationship: contact ${data.id} -> group ${data.group_id}`
            );
          }
        } else {
          console.log(
            "🔄 No group changes requested, keeping existing relationships"
          );
        }

        // 4️⃣ Commit transaction
        await connection.commit();
        console.log("✅ Transaction committed successfully");

        return res.status(200).json({
          success: true,
          message: "✅ อัพเดทสำเร็จ รวมถึงการจัดการกลุ่ม",
          statusCode: 200,
        });
      } catch (transactionError) {
        // ❌ Rollback on error
        await connection.rollback();
        console.error("❌ Transaction rolled back:", transactionError);
        throw transactionError;
      } finally {
        connection.release();
      }
    } catch (error: any) {
      console.error("❌ contactUpdateUser Error:", error);
      return res.status(500).json({
        success: false,
        message: "❌ อัพเดทไม่สำเร็จ: " + (error.message || "เกิดข้อผิดพลาด"),
        statusCode: 500,
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
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );
        return res.status(400).json({
          success: false,
          message: `${errors.join(",")}`,
          statusCode: 400,
        });
      }
      const del = result.data?.id.map(() => "?").join(",");
      const id = result.data?.id;
      await pool.query("START TRANSACTION");

      try {
        // 1. ลบความสัมพันธ์ใน count_groups ก่อน
        const deleteCountGroupsSql = `
          DELETE FROM count_groups WHERE contact_id IN (${del})
        `;
        await pool.query(deleteCountGroupsSql, id);

        // 2. ลบข้อมูลใน contact
        const deleteContactSql = `
          DELETE FROM contact WHERE id IN (${del})
        `;
        await pool.query(deleteContactSql, id);

        // Commit transaction
        await pool.query("COMMIT");

        return res.status(200).json({
          success: true,
          message: "✅ ลบข้อมูลสำเร็จ",
          statusCode: 200,
        });
      } catch (transactionError) {
        // Rollback transaction ถ้าเกิดข้อผิดพลาด
        await pool.query("ROLLBACK");
        throw transactionError;
      }
    } catch (error: any) {
      console.error("❌ contactDelete Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ ลบข้อมูลไม่สำเร็จ",
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
    const sql = `
      SELECT 
      cg.id,
        cg.group_name,
        cg.contact_id,
        cg.create_date,
        cg.last_update,
        COUNT(ccg.contact_id) as contact_count,
        COUNT(CASE WHEN c.phone IS NOT NULL AND c.phone != '' THEN 1 END) as phone_count,
        COUNT(CASE WHEN c.email IS NOT NULL AND c.email != '' THEN 1 END) as email_count
      FROM contact_groups cg
      LEFT JOIN count_groups ccg ON cg.id = ccg.groups_id
      LEFT JOIN contact c ON ccg.contact_id = c.id
      GROUP BY cg.id, cg.group_name, cg.contact_id, cg.create_date, cg.last_update
      ORDER BY cg.create_date DESC
      ;
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
      group_name = ?, contact_id = ?, last_update = ?
      where id = ?;
    `;

      await pool.query(sql, [
        data.group_name,
        data.contact_id,
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
      if (result.success === false) {
        const errors = result.error.errors.map(
          (err) => `${err.path.join(",")}:${err.message}`
        );
        return res.status(400).json({
          success: false,
          message: `${errors.join(",")}`,
          statusCode: 400,
        });
      }
      const del = result.data?.id.map(() => "?").join(",");
      const id = result.data?.id;
      // เริ่ม transaction
      await pool.query("START TRANSACTION");

      try {
        // 1. ลบความสัมพันธ์ใน count_groups ก่อน
        const deleteCountGroupsSql = `
          DELETE FROM count_groups WHERE groups_id IN (${del})
        `;
        await pool.query(deleteCountGroupsSql, id);

        // 2. ลบข้อมูลใน contact_groups
        const deleteGroupsSql = `
          DELETE FROM contact_groups WHERE id IN (${del})
        `;
        await pool.query(deleteGroupsSql, id);

        // Commit transaction
        await pool.query("COMMIT");

        return res.status(200).json({
          success: true,
          message: "✅ ลบข้อมูลสำเร็จ",
          statusCode: 200,
        });
      } catch (transactionError) {
        // Rollback transaction ถ้าเกิดข้อผิดพลาด
        await pool.query("ROLLBACK");
        throw transactionError;
      }
    } catch (error: any) {
      console.error("❌ contactDeletegroups Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ ลบข้อมูลไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region countgroups
  async countgroups(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
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
      FROM contact ;
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
        message: "❌ อัพเดทไม่สำเร็จ",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region contactAddToGroup
  async contactAddToGroup(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      // 1) กรณีเพิ่ม "รายชื่อใหม่" และระบุกลุ่ม -> ใช้ contactSchema (ทำงานเดิม)
      // 2) กรณีเพิ่ม "รายชื่อที่มีอยู่แล้วหลายคน" เข้ากลุ่ม -> ใช้ addExistingContactsToGroupSchema

      // เช็คว่า body มี contact_ids หรือไม่ ถ้ามีให้ตีความว่าเป็นการเพิ่มรายชื่อที่มีอยู่แล้วเข้ากลุ่ม
      if (Array.isArray((req.body as any)?.contact_ids)) {
        const parsed = addExistingContactsToGroupSchema.safeParse(req.body);
        if (!parsed.success) {
          const errors = parsed.error.errors
            .map((err) => `${err.path.join(",")}:${err.message}`)
            .join(", ");

          return res.status(400).json({
            success: false,
            message: errors,
            statusCode: 400,
          });
        }

        const { contact_ids, group_id } = parsed.data;

        // ตรวจสอบว่ากลุ่มมีอยู่จริง
        const [groupExists] = await pool.query(
          "SELECT id FROM contact_groups WHERE id = ?",
          [group_id]
        );
        if ((groupExists as any[]).length === 0) {
          return res.status(400).json({
            success: false,
            message: "ไม่พบกลุ่มที่ระบุ",
            statusCode: 400,
          });
        }

        // เพิ่มเฉพาะความสัมพันธ์ที่ยังไม่มีอยู่ใน count_groups
        const placeholders = contact_ids.map(() => "(? , ?)").join(",");
        const values: any[] = [];

        // หา contact ที่ยังไม่ได้อยู่ในกลุ่มนี้
        const idsPlaceholder = contact_ids.map(() => "?").join(",");
        const [existing] = await pool.query(
          `SELECT contact_id FROM count_groups WHERE groups_id = ? AND contact_id IN (${idsPlaceholder})`,
          [group_id, ...contact_ids]
        );
        const existingIds = new Set(
          (existing as any[]).map((r) => r.contact_id)
        );
        const idsToInsert = contact_ids.filter((id) => !existingIds.has(id));

        if (idsToInsert.length === 0) {
          return res.status(200).json({
            success: true,
            message: "ไม่มีสมาชิกใหม่ต้องเพิ่ม (ซ้ำทั้งหมด)",
            statusCode: 200,
            data: { inserted: 0, group_id, contact_ids: [] },
          });
        }

        idsToInsert.forEach((cid) => {
          values.push(group_id, cid);
        });

        const sql = `INSERT INTO count_groups (groups_id, contact_id) VALUES ${idsToInsert
          .map(() => "(?, ?)")
          .join(",")}`;

        const [insertResult]: any = await pool.query(sql, values);

        return res.status(200).json({
          success: true,
          message: `✅ เพิ่มสมาชิกใหม่ ${idsToInsert.length} คนเข้ากลุ่มสำเร็จ`,
          statusCode: 200,
          data: {
            inserted: idsToInsert.length,
            group_id,
            contact_ids: idsToInsert,
          },
        });
      }
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

      // ตรวจสอบว่ามี group_id
      if (!data.group_id) {
        return res.status(400).json({
          success: false,
          message: "ต้องระบุ group_id",
          statusCode: 400,
        });
      }

      // ตรวจสอบว่ามี user_id
      if (!data.user_id) {
        return res.status(400).json({
          success: false,
          message: "ต้องระบุ user_id",
          statusCode: 400,
        });
      }

      // ตรวจสอบว่ากลุ่มมีอยู่จริง
      const [groupExists] = await pool.query(
        "SELECT id FROM contact_groups WHERE id = ?",
        [data.group_id]
      );

      if ((groupExists as any[]).length === 0) {
        return res.status(400).json({
          success: false,
          message: "ไม่พบกลุ่มที่ระบุ",
          statusCode: 400,
        });
      }

      // เริ่ม transaction
      await pool.query("START TRANSACTION");

      try {
        // 1. บันทึกข้อมูลรายชื่อลงตาราง contact
        const contactSql = `
          INSERT INTO contact
          (first_name, last_name, phone, email, birth_date, user_id)
          VALUES (?, ?, ?, ?, ?, ?)
        `;

        const [contactResult]: any = await pool.query(contactSql, [
          data.first_name,
          data.last_name,
          data.phone,
          data.email,
          data.birth_date,
          data.user_id,
        ]);

        const contactId = contactResult.insertId;

        // 2. บันทึกความสัมพันธ์ลงตาราง count_groups
        const countGroupsSql = `
          INSERT INTO count_groups
          (groups_id, contact_id)
          VALUES (?, ?)
        `;

        await pool.query(countGroupsSql, [data.group_id, contactId]);

        // Commit transaction
        await pool.query("COMMIT");

        return res.status(200).json({
          success: true,
          message: "✅ เพิ่มรายชื่อเข้ากลุ่มสำเร็จ",
          statusCode: 200,
          data: {
            contact_id: contactId,
            group_id: data.group_id,
          },
        });
      } catch (transactionError) {
        // Rollback transaction ถ้าเกิดข้อผิดพลาด
        await pool.query("ROLLBACK");
        throw transactionError;
      }
    } catch (error: any) {
      console.error("❌ contactAddToGroup Error:", error);
      return res.status(404).json({
        success: false,
        message: "❌ ไม่สามารถเพิ่มรายชื่อเข้ากลุ่มได้",
        statusCode: 404,
      });
    }
  }
  //#endregion

  //#region removeFromGroup - ลบสมาชิกออกจากกลุ่ม
  async removeFromGroup(
    req: Request,
    res: Response<apiResponse>
  ): Promise<Response<apiResponse>> {
    try {
      const { contact_ids, group_id } = req.body;

      // ตรวจสอบข้อมูลที่จำเป็น
      if (
        !contact_ids ||
        !Array.isArray(contact_ids) ||
        contact_ids.length === 0
      ) {
        return res.status(400).json({
          success: false,
          message: "ต้องระบุ contact_ids เป็น array",
          statusCode: 400,
        });
      }

      if (!group_id) {
        return res.status(400).json({
          success: false,
          message: "ต้องระบุ group_id",
          statusCode: 400,
        });
      }

      // ตรวจสอบว่ากลุ่มมีอยู่จริง
      const [groupExists] = await pool.query(
        "SELECT id FROM contact_groups WHERE id = ?",
        [group_id]
      );

      if ((groupExists as any[]).length === 0) {
        return res.status(400).json({
          success: false,
          message: "ไม่พบกลุ่มที่ระบุ",
          statusCode: 400,
        });
      }

      // เริ่ม transaction
      await pool.query("START TRANSACTION");

      try {
        // ลบความสัมพันธ์จากตาราง count_groups
        const placeholders = contact_ids.map(() => "?").join(",");
        const deleteSql = `
          DELETE FROM count_groups 
          WHERE contact_id IN (${placeholders}) AND groups_id = ?
        `;

        const [deleteResult]: any = await pool.query(deleteSql, [
          ...contact_ids,
          group_id,
        ]);

        // Commit transaction
        await pool.query("COMMIT");

        return res.status(200).json({
          success: true,
          message: `✅ ลบสมาชิก ${deleteResult.affectedRows} คนออกจากกลุ่มสำเร็จ`,
          statusCode: 200,
          data: {
            removed_count: deleteResult.affectedRows,
            contact_ids: contact_ids,
            group_id: group_id,
          },
        });
      } catch (transactionError) {
        // Rollback transaction ถ้าเกิดข้อผิดพลาด
        await pool.query("ROLLBACK");
        throw transactionError;
      }
    } catch (error: any) {
      console.error("❌ removeFromGroup Error:", error);
      return res.status(500).json({
        success: false,
        message: "❌ ไม่สามารถลบสมาชิกออกจากกลุ่มได้",
        statusCode: 500,
      });
    }
  }
  //#endregion
}
