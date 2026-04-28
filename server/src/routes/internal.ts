import { Router } from "express";
import bcrypt from "bcrypt";
import { z } from "zod";
import { query } from "../db.js";
import { config } from "../config.js";

const router = Router();

// Internal API secret middleware
const requireInternalSecret = (
  req: import("express").Request,
  res: import("express").Response,
  next: import("express").NextFunction,
) => {
  const secret = req.headers["x-internal-secret"];
  if (!config.internalApiSecret || secret !== config.internalApiSecret) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
};

router.use(requireInternalSecret);

// ── POST /api/internal/provision-user ───
// Creates a Baikalsphere user + grants module access.
// Called by module backends (e.g. AR) when creating sub-users.

const provisionSchema = z.object({
  email: z.string().email().max(320),
  fullName: z.string().min(1).max(200),
  passwordHash: z.string().min(1),
  moduleIds: z.array(z.string()).default([]),
});

router.post("/provision-user", async (req, res) => {
  try {
    const body = provisionSchema.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: "Validation failed", details: body.error.flatten().fieldErrors });
      return;
    }

    const { email, fullName, passwordHash, moduleIds } = body.data;

    // Check if user already exists
    const existing = await query(`SELECT id FROM users WHERE email = $1`, [email]);
    let userId: string;

    if (existing!.rows.length > 0) {
      userId = existing!.rows[0].id;
    } else {
      const result = await query(
        `INSERT INTO users (email, password_hash, full_name, platform_role)
         VALUES ($1, $2, $3, 'member')
         RETURNING id`,
        [email, passwordHash, fullName]
      );
      userId = result!.rows[0].id;
    }

    // Grant module access
    for (const moduleId of moduleIds) {
      await query(
        `INSERT INTO user_modules (user_id, module_id) VALUES ($1, $2)
         ON CONFLICT (user_id, module_id) DO NOTHING`,
        [userId, moduleId]
      );
    }

    res.status(201).json({ userId });
  } catch (err) {
    console.error("Provision user error:", err);
    res.status(500).json({ error: "Failed to provision user" });
  }
});

// ── POST /api/internal/provision-organization ───
// Creates/updates a Baikalsphere organization from AR module.
// Also creates/updates a corporate user with the credentials.
// Called by AR backend when hotel creates a corporate organization.

const provisionOrgSchema = z.object({
  arOrgId: z.string().min(1).max(100),         // AR's organization ID (e.g. "ORG-123")
  name: z.string().min(1).max(200),
  contactEmail: z.string().email().max(320),
  corporatePasswordHash: z.string().min(1),    // Bcrypt hash of the corporate password
  gst: z.string().max(64).optional().nullable(),
  industry: z.string().max(100).optional().default("hospitality"),
  createdByArUserId: z.string().optional(),    // AR user who created it (for audit)
});

router.post("/provision-organization", async (req, res) => {
  try {
    const body = provisionOrgSchema.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: "Validation failed", details: body.error.flatten().fieldErrors });
      return;
    }

    const { arOrgId, name, contactEmail, corporatePasswordHash, gst, industry } = body.data;
    
    // Generate slug from name
    const baseSlug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 50);
    const slug = `${baseSlug}-${arOrgId.toLowerCase().replace(/[^a-z0-9]/g, "")}`;

    // Check if organization already exists (by AR org ID in metadata or slug)
    const existing = await query(
      `SELECT id FROM organizations WHERE slug = $1`,
      [slug]
    );

    let orgId: string;
    let isNew = false;

    if (existing!.rows.length > 0) {
      // Update existing organization
      orgId = existing!.rows[0].id;
      await query(
        `UPDATE organizations 
         SET name = $1, industry = $2, updated_at = now()
         WHERE id = $3`,
        [name, industry, orgId]
      );
    } else {
      // Create new organization
      isNew = true;
      const result = await query(
        `INSERT INTO organizations (name, slug, industry, is_active)
         VALUES ($1, $2, $3, true)
         RETURNING id`,
        [name, slug, industry]
      );
      orgId = result!.rows[0].id;
    }

    // Create or update the corporate user with the same credentials
    const normalizedEmail = contactEmail.toLowerCase();
    const existingUser = await query(
      `SELECT id FROM users WHERE email = $1`,
      [normalizedEmail]
    );

    let userId: string;
    if (existingUser!.rows.length > 0) {
      userId = existingUser!.rows[0].id;
      // Update password hash to keep in sync
      await query(
        `UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`,
        [corporatePasswordHash, userId]
      );
    } else {
      // Create new user with corporate email and password
      const userResult = await query(
        `INSERT INTO users (email, password_hash, full_name, platform_role)
         VALUES ($1, $2, $3, 'member')
         RETURNING id`,
        [normalizedEmail, corporatePasswordHash, name]
      );
      userId = userResult!.rows[0].id;
    }

    // Grant AR module access
    await query(
      `INSERT INTO user_modules (user_id, module_id) VALUES ($1, 'ar')
       ON CONFLICT (user_id, module_id) DO NOTHING`,
      [userId]
    );

    // Associate user with organization
    await query(
      `UPDATE users SET organization_id = $1 WHERE id = $2`,
      [orgId, userId]
    );

    console.log(`[internal] Provisioned org ${arOrgId} -> ${orgId}, user ${normalizedEmail} -> ${userId}`);

    res.status(201).json({ 
      organizationId: orgId,
      slug,
      isNew
    });
  } catch (err) {
    console.error("Provision organization error:", err);
    res.status(500).json({ error: "Failed to provision organization" });
  }
});

// ── POST /api/internal/sync-user-password ───
// Updates password hash for a user by email. Called by AR when a hotel
// user changes their password so both systems stay in sync.

const syncPasswordSchema = z.object({
  email: z.string().email().max(320),
  passwordHash: z.string().min(1),
});

router.post("/sync-user-password", async (req, res) => {
  try {
    const body = syncPasswordSchema.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: "Validation failed", details: body.error.flatten().fieldErrors });
      return;
    }

    const { email, passwordHash } = body.data;

    const result = await query(
      `UPDATE users SET password_hash = $1, failed_login_attempts = 0, locked_until = NULL, updated_at = now()
       WHERE email = $2
       RETURNING id`,
      [passwordHash, email.toLowerCase()]
    );

    if (result!.rows.length === 0) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("Sync password error:", err);
    res.status(500).json({ error: "Failed to sync password" });
  }
});

// ── GET /api/internal/organization-by-ar-id/:arOrgId ───
// Lookup a Baikalsphere organization by AR organization ID
router.get("/organization-by-ar-id/:arOrgId", async (req, res) => {
  try {
    const { arOrgId } = req.params;
    const slugSuffix = arOrgId.toLowerCase().replace(/[^a-z0-9]/g, "");
    
    const result = await query(
      `SELECT id, name, slug, industry, is_active 
       FROM organizations 
       WHERE slug LIKE $1`,
      [`%-${slugSuffix}`]
    );

    if (result!.rows.length === 0) {
      res.status(404).json({ error: "Organization not found" });
      return;
    }

    res.json({ organization: result!.rows[0] });
  } catch (err) {
    console.error("Lookup organization error:", err);
    res.status(500).json({ error: "Failed to lookup organization" });
  }
});

export default router;
