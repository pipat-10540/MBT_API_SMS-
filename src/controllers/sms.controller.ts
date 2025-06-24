import axios from "axios";
import { Request, Response } from "express";
import dotenv from "dotenv";

dotenv.config();

export const sendSMS = async (req: Request, res: Response) => {
  const { phone, message } = req.body;

  const msisdn = phone.startsWith("0") ? "66" + phone.slice(1) : phone;

  try {
    const response = await axios.post(
      "https://api-v2.thaibulksms.com/sms",
      {
        msisdn: msisdn,
        message,
        sender: "Demo",
        force: "corporate",
        shorten_url: false,
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

    res.json({ status: "success", data: response.data });
  } catch (error: any) {
    console.error(
      "❌ ThaiBulkSMS Error:",
      error.response?.data || error.message
    );
    res.status(500).json({
      status: "error",
      message: error.message,
    });
  }
};
