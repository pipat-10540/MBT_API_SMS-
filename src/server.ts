import express, { Application } from "express";
import cors, { CorsOptions } from "cors";
import Routes from "./routes";

export default class Server {
  constructor(app: Application) {
    this.config(app);
    new Routes(app);
  }

  private config(app: Application): void {
    app.use(
      cors({
        origin: "http://localhost:3000", // ให้ allow origin ของ frontend
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true, // ถ้ามี cookie หรือ auth header
      })
    );
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
  }
}
