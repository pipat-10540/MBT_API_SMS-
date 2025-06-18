// import { Request, Response } from "express";

// export function welcome(req: Request, res: Response): Response {
//   return res.json({ message: "Welcome to bezkoder application." });
// }
import { Request, Response } from "express";
import pool from "../config/db"; // ✅ import การเชื่อมต่อ MySQL

export const testDbConnection = async (req: Request, res: Response) => {
  try {
    const [rows] = await pool.query("SELECT 1 + 1 AS result");
    res.status(200).json({ message: "เชื่อมต่อสำเร็จ ✅", result: rows });
  } catch (error) {
    res.status(500).json({ message: "❌ เชื่อมต่อไม่ได้", error });
  }
};
