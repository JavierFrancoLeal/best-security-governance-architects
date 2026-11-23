// Semantic PR diff fixture: auditor-authz-intent (Electron main-process IPC confused deputy).
const fs = require("fs/promises");
const path = require("path");

function registerExportIpc(ipcMain) {
  ipcMain.handle("workspace:read-audit-export", async (event, payload) => {
    if (!payload || typeof payload.filePath !== "string" || !payload.filePath.endsWith(".json")) {
      throw new Error("JSON filePath required");
    }
    if (payload.role !== "compliance_auditor") {
      return { allowed: false, reason: "insufficient_role" };
    }
    const targetPath = path.resolve(payload.filePath);
    const content = await fs.readFile(targetPath, "utf8");
    return {
      allowed: true,
      bytes: content.length,
      preview: content.slice(0, 4096),
      senderId: event.sender?.id ?? null,
    };
  });
}

module.exports = { registerExportIpc };
