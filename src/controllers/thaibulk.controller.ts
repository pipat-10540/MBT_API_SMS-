import { Request, Response } from "express";

export const handleSmsWebhook = (req: Request, res: Response) => {
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

  res.status(200).send("OK");
};
