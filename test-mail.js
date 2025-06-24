// import nodemailer from "nodemailer";
// import dotenv from "dotenv";

// dotenv.config(); // โหลดค่าจาก .env

// const transporter = nodemailer.createTransport({
//   service: "gmail",
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS,
//   },
// });

// const mailOptions = {
//   from: `"Test Sender" <${process.env.EMAIL_USER}>`,
//   to: "อีเมลผู้รับ@gmail.com", // ✅ ต้องใส่
//   subject: "ทดสอบส่งเมล",
//   text: "นี่คืออีเมลทดสอบจากระบบ MBT",
// };

// transporter.sendMail(mailOptions, (error, info) => {
//   if (error) {
//     console.error("❌ ส่งเมลไม่สำเร็จ:", error.message);
//   } else {
//     console.log("✅ ส่งเมลสำเร็จ:", info.response);
//   }
// });
