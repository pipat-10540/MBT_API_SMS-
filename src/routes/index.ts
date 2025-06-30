import userRoutes from "./user.routes";
import express, { Router } from "express";

const router = express.Router();

router.use("/api/users", userRoutes);
// router.use("/api", userRoutes);
// app.use("/webhook", userRoutes);

export default router;
