import express from "express";
import { exec } from "child_process";

const app = express();

app.get("/users/:id", requireAuth, async (req, res) => {
  const user = await repository.findById(req.params.id);
  return res.json(user);
});

app.post("/reports", validateReport, (req, res) => {
  exec(req.body.command);
  res.redirect("/reports");
});

function requireAuth() { return true; }
function validateReport() { return true; }
