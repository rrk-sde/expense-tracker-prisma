import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import Pusher from 'pusher';
import { onCreateTransaction } from './actions/transaction.action.js';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { promisify } from 'util';

dotenv.config();

// Bypass SSL certificate issues for local development (fixes Pusher SELF_SIGNED_CERT_IN_CHAIN error)
if (process.env.NODE_ENV !== 'production') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

const prisma = new PrismaClient();
const scryptAsync = promisify(crypto.scrypt);

const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID || 'dummy_id',
  key: process.env.PUSHER_KEY || 'dummy_key',
  secret: process.env.PUSHER_SECRET || 'dummy_secret',
  cluster: process.env.PUSHER_CLUSTER || 'dummy_cluster',
  useTLS: true,
});

const normalizeEmail = (email: string) => String(email || '').trim().toLowerCase();

const hashToken = (value: string) => crypto.createHash('sha256').update(value).digest('hex');

const hashPassword = async (password: string) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${salt}:${derived.toString('hex')}`;
};

const verifyPassword = async (password: string, storedHash: string) => {
  const [salt, hashHex] = String(storedHash || '').split(':');
  if (!salt || !hashHex) return false;

  const derived = (await scryptAsync(password, salt, 64)) as Buffer;
  const hashBuffer = Buffer.from(hashHex, 'hex');

  if (derived.length !== hashBuffer.length) return false;
  return crypto.timingSafeEqual(derived, hashBuffer);
};

const sanitizeUser = (user: any) => ({
  id: user.id,
  email: user.email,
  name: user.name,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

// Pusher Auth Endpoint for Presence Channels
app.post('/api/pusher/auth', (req, res) => {
  const socketId = req.body.socket_id;
  const channel = req.body.channel_name;

  const presenceData = {
    user_id: `user_${Math.floor(Math.random() * 10000)}`,
    user_info: { name: 'Anonymous Analyst' },
  };

  try {
    const authResponse = pusher.authorizeChannel(socketId, channel, presenceData);
    res.send(authResponse);
  } catch (err) {
    console.error(err);
    res.status(403).send('Forbidden');
  }
});

app.get('/api/vaults/:vaultId/transactions', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const userId = String(req.query.userId || '');
    const cursor = req.query.cursor ? String(req.query.cursor) : null;
    const q = String(req.query.q || '').trim();
    const creatorId = String(req.query.creatorId || '').trim();
    const year = req.query.year ? Number(req.query.year) : null;
    const month = req.query.month ? Number(req.query.month) : null;
    const from = req.query.from ? new Date(String(req.query.from)) : null;
    const to = req.query.to ? new Date(String(req.query.to)) : null;
    const limit = Math.min(Math.max(Number(req.query.limit || 30), 1), 100);

    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const membership = await prisma.userVault.findFirst({ where: { userId, vaultId } });
    if (!membership) {
      return res.status(403).json({ error: 'Not allowed to view this space' });
    }

    const where: any = { vaultId };

    if (q) {
      where.title = { contains: q, mode: 'insensitive' };
    }

    if (creatorId) {
      where.creatorId = creatorId;
    }

    const createdAt: any = {};
    if (year || month) {
      const resolvedYear = year || new Date().getFullYear();
      const resolvedMonthIndex = month ? Math.max(1, Math.min(12, month)) - 1 : 0;
      const start = month ? new Date(resolvedYear, resolvedMonthIndex, 1) : new Date(resolvedYear, 0, 1);
      const end = month ? new Date(resolvedYear, resolvedMonthIndex + 1, 1) : new Date(resolvedYear + 1, 0, 1);
      createdAt.gte = start;
      createdAt.lt = end;
    } else {
      if (from && !Number.isNaN(from.getTime())) createdAt.gte = from;
      if (to && !Number.isNaN(to.getTime())) createdAt.lte = to;
    }

    if (Object.keys(createdAt).length > 0) {
      where.createdAt = createdAt;
    }

    const [rows, totalCount] = await Promise.all([
      prisma.transaction.findMany({
        where,
        include: {
          items: true,
          creator: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        cursor: cursor ? { id: cursor } : undefined,
        skip: cursor ? 1 : 0,
        take: limit + 1,
      }),
      prisma.transaction.count({ where }),
    ]);

    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = hasMore ? items[items.length - 1]?.id : null;

    return res.json({
      items,
      nextCursor,
      hasMore,
      totalCount,
    });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

app.get('/api/vaults/:vaultId/velocity', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const userId = String(req.query.userId || '');
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const membership = await prisma.userVault.findFirst({ where: { userId, vaultId } });
    if (!membership) {
      return res.status(403).json({ error: 'Not allowed to view this space' });
    }

    const velocityResult = await prisma.transaction.aggregate({
      where: {
        vaultId,
        createdAt: {
          gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        },
      },
      _sum: { amount: true },
      _count: true,
    });

    const spendingVelocity = {
      totalAmount7d: velocityResult._sum.amount || 0,
      count7d: velocityResult._count || 0,
    };

    res.json(spendingVelocity);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/transactions', async (req, res) => {
  try {
    const { title, amount, vaultId, creatorId } = req.body;

    if (!title || !vaultId || !creatorId || Number(amount) <= 0) {
      return res.status(400).json({ error: 'title, amount, vaultId and creatorId are required' });
    }

    const membership = await prisma.userVault.findFirst({ where: { userId: creatorId, vaultId } });
    if (!membership) {
      return res.status(403).json({ error: 'Not allowed to post in this space' });
    }

    const result = await onCreateTransaction({
      ...req.body,
      amount: Number(amount),
    });
    return res.status(201).json(result);
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

app.delete('/api/transactions/:transactionId', async (req, res) => {
  try {
    const transactionId = req.params.transactionId;
    const actorUserId = String(req.body?.userId || req.query.userId || '');

    if (!actorUserId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const transaction = await prisma.transaction.findUnique({
      where: { id: transactionId },
    });

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const membership = await prisma.userVault.findFirst({
      where: {
        userId: actorUserId,
        vaultId: transaction.vaultId,
      },
    });

    if (!membership) {
      return res.status(403).json({ error: 'Not allowed in this space' });
    }

    const canDelete = transaction.creatorId === actorUserId || membership.role === 'OWNER' || membership.role === 'ADMIN';
    if (!canDelete) {
      return res.status(403).json({ error: 'Only creator/admin/owner can delete this transaction' });
    }

    await prisma.transaction.delete({ where: { id: transactionId } });

    const velocityResult = await prisma.transaction.aggregate({
      where: {
        vaultId: transaction.vaultId,
        createdAt: {
          gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        },
      },
      _sum: { amount: true },
      _count: true,
    });

    const spendingVelocity = {
      totalAmount7d: velocityResult._sum.amount || 0,
      count7d: velocityResult._count || 0,
    };

    const channelName = `presence-vault-${transaction.vaultId}`;
    await Promise.all([
      pusher.trigger(channelName, 'transaction.deleted', { transactionId }),
      pusher.trigger(channelName, 'analytics.velocity_updated', { spendingVelocity }),
    ]);

    return res.json({
      success: true,
      transactionId,
      title: transaction.title,
      amount: transaction.amount
    });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, name, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || !password || String(password).length < 8) {
    return res.status(400).json({ error: 'Valid email and password (min 8 chars) are required' });
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await hashPassword(String(password));
    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        name: name || normalizedEmail.split('@')[0],
        passwordHash,
      },
    });

    return res.status(201).json(sanitizeUser(user));
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValid = await verifyPassword(String(password), user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    return res.json(sanitizeUser(user));
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Google OAuth Mock/Real Endpoint
app.post('/api/auth/google', async (req: express.Request, res: express.Response) => {
  const { email, name, providerId } = req.body;
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    let user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (!user) {
      user = await prisma.user.create({
        data: {
          email: normalizedEmail,
          name: name || 'Google User',
          // Random password for OAuth users to satisfy schema
          passwordHash: await hashPassword(crypto.randomBytes(16).toString('hex')),
        },
      });
    }

    return res.status(200).json(sanitizeUser(user));
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Guest
app.post('/api/auth/guest', async (req: express.Request, res: express.Response) => {
  try {
    const rawId = crypto.randomBytes(4).toString('hex');
    const email = `guest_${rawId}@example.com`;
    const user = await prisma.user.create({
      data: {
        email,
        name: 'Guest User',
      },
    });
    return res.status(201).json(sanitizeUser(user));
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    // Keep response shape similar to avoid user-enumeration via status code.
    if (!user) {
      return res.json({ success: true, message: 'If the email exists, a reset token has been generated.' });
    }

    const rawToken = crypto.randomBytes(24).toString('hex').toUpperCase();
    const hashed = hashToken(rawToken);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetTokenHash: hashed,
        resetTokenExpires: new Date(Date.now() + 15 * 60 * 1000),
      },
    });

    return res.json({
      success: true,
      message: 'Reset token generated.',
      resetToken: rawToken, // Demo-only until email provider is integrated.
      expiresInMinutes: 15,
    });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || !token || !newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ error: 'Email, token and new password (min 8 chars) are required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (!user?.resetTokenHash || !user.resetTokenExpires || user.resetTokenExpires.getTime() < Date.now()) {
      return res.status(400).json({ error: 'Reset token is invalid or expired' });
    }

    const incomingHash = hashToken(String(token).trim().toUpperCase());
    if (incomingHash !== user.resetTokenHash) {
      return res.status(400).json({ error: 'Reset token is invalid or expired' });
    }

    const passwordHash = await hashPassword(String(newPassword));
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        resetTokenHash: null,
        resetTokenExpires: null,
      },
    });

    return res.json({ success: true, message: 'Password reset successful' });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/:userId/vaults', async (req, res) => {
  try {
    const userVaults = await prisma.userVault.findMany({
      where: { userId: req.params.userId },
      include: {
        vault: {
          include: {
            _count: {
              select: { members: true },
            },
          },
        },
      },
      orderBy: { vault: { createdAt: 'desc' } },
    });
    const vaultsData = await Promise.all(
      userVaults.map(async (uv: any) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const sums: any[] = await (prisma.transaction.groupBy as any)({
          by: ['type'],
          where: { vaultId: uv.vault.id },
          _sum: { amount: true },
        });

        const total = sums.reduce((acc, group) => {
          const amt = group._sum?.amount || 0;
          return group.type === 'CR' ? acc - amt : acc + amt;
        }, 0);

        return {
          id: uv.vault.id,
          name: uv.vault.name,
          description: uv.vault.description,
          createdAt: uv.vault.createdAt,
          updatedAt: uv.vault.updatedAt,
          memberCount: uv.vault._count?.members ?? 1,
          totalAmount: total,
        };
      })
    );
    res.json(vaultsData);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/:userId/summary', async (req, res) => {
  try {
    const memberships = await prisma.userVault.findMany({
      where: { userId: req.params.userId },
      select: { vaultId: true },
    });

    const vaultIds = memberships.map((m) => m.vaultId);
    if (vaultIds.length === 0) {
      return res.json({ spaceCount: 0, totalAmount7d: 0, transactionCount7d: 0, activeSpaces: 0 });
    }

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const [aggregate, activeSpaces] = await Promise.all([
      prisma.transaction.aggregate({
        where: {
          vaultId: { in: vaultIds },
          createdAt: { gte: sevenDaysAgo },
        },
        _sum: { amount: true },
        _count: true,
      }),
      prisma.transaction.groupBy({
        by: ['vaultId'],
        where: {
          vaultId: { in: vaultIds },
          createdAt: { gte: sevenDaysAgo },
        },
      }),
    ]);

    return res.json({
      spaceCount: vaultIds.length,
      totalAmount7d: aggregate._sum.amount || 0,
      transactionCount7d: aggregate._count || 0,
      activeSpaces: activeSpaces.length,
    });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

app.post('/api/vaults', async (req, res) => {
  const { name, userId } = req.body;
  try {
    const vault = await prisma.vault.create({
      data: {
        name,
        members: {
          create: { userId, role: 'OWNER' },
        },
      },
    });
    res.status(201).json(vault);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/vaults/join', async (req, res) => {
  const { code, userId } = req.body;
  const normalizedCode = String(code || '').trim().toLowerCase();

  if (!normalizedCode || !userId) {
    return res.status(400).json({ error: 'code and userId are required' });
  }

  try {
    const matchingVaults = await prisma.vault.findMany({
      where: { id: { startsWith: normalizedCode } },
      orderBy: { createdAt: 'desc' },
      take: 2,
    });

    if (matchingVaults.length === 0) {
      return res.status(404).json({ error: 'Space not found for this invite code' });
    }

    if (matchingVaults.length > 1) {
      return res.status(409).json({ error: 'Invite code is ambiguous. Use a longer code.' });
    }

    const vault = matchingVaults[0];

    const existingMembership = await prisma.userVault.findFirst({
      where: {
        userId,
        vaultId: vault.id,
      },
    });

    if (!existingMembership) {
      await prisma.userVault.create({
        data: {
          userId,
          vaultId: vault.id,
          role: 'MEMBER',
        },
      });
    }

    return res.status(200).json(vault);
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

app.get('/api/vaults/:vaultId/members', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const actorUserId = String(req.query.userId || '');
    if (!actorUserId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const actorMembership = await prisma.userVault.findFirst({
      where: { userId: actorUserId, vaultId },
    });

    if (!actorMembership) {
      return res.status(403).json({ error: 'Not allowed to view members' });
    }

    const members = await prisma.userVault.findMany({
      where: { vaultId },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
          },
        },
      },
      orderBy: { role: 'asc' },
    });

    return res.json(
      members.map((m) => ({
        userId: m.userId,
        role: m.role,
        email: m.user.email,
        name: m.user.name,
      }))
    );
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

app.post('/api/vaults/:vaultId/members/remove', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const { actorUserId, targetUserId } = req.body;

    if (!actorUserId || !targetUserId) {
      return res.status(400).json({ error: 'actorUserId and targetUserId are required' });
    }

    const actorMembership = await prisma.userVault.findFirst({
      where: { userId: actorUserId, vaultId },
    });

    if (!actorMembership || !['OWNER', 'ADMIN'].includes(actorMembership.role)) {
      return res.status(403).json({ error: 'Only owner/admin can remove members' });
    }

    const targetMembership = await prisma.userVault.findFirst({
      where: { userId: targetUserId, vaultId },
    });

    if (!targetMembership) {
      return res.status(404).json({ error: 'Target member not found' });
    }

    if (targetMembership.role === 'OWNER') {
      return res.status(400).json({ error: 'Owner cannot be removed' });
    }

    if (actorUserId === targetUserId) {
      return res.status(400).json({ error: 'Use leave action for self-removal' });
    }

    await prisma.userVault.delete({
      where: {
        userId_vaultId: {
          userId: targetUserId,
          vaultId,
        },
      },
    });

  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Delete space (owner only)
app.delete('/api/vaults/:vaultId', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const actorUserId = String(req.body?.userId || req.query.userId || '');

    if (!actorUserId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const membership = await prisma.userVault.findFirst({
      where: { userId: actorUserId, vaultId },
    });

    if (!membership || membership.role !== 'OWNER') {
      return res.status(403).json({ error: 'Only the owner can delete the space entirely' });
    }

    await prisma.vault.delete({
      where: { id: vaultId },
    });

    return res.json({ success: true, message: 'Vault deleted successfully' });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

// Leave space (members/admins)
app.post('/api/vaults/:vaultId/leave', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const actorUserId = String(req.body?.userId || req.query.userId || '');

    if (!actorUserId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const membership = await prisma.userVault.findFirst({
      where: { userId: actorUserId, vaultId },
    });

    if (!membership) {
      return res.status(404).json({ error: 'You are not a member of this space' });
    }

    if (membership.role === 'OWNER') {
      // Check if they are the only member
      const memberCount = await prisma.userVault.count({ where: { vaultId } });
      if (memberCount > 1) {
        return res.status(403).json({ error: 'Owner cannot leave while others exist. Delete the space or transfer ownership.' });
      }

      // If only member, leaving is equivalent to deleting
      await prisma.vault.delete({ where: { id: vaultId } });
      return res.json({ success: true, message: 'Vault deleted since you were the last member' });
    }

    // Normal member leaving
    await prisma.userVault.delete({
      where: {
        userId_vaultId: {
          userId: actorUserId,
          vaultId,
        },
      },
    });

    return res.json({ success: true, message: 'Left space successfully' });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

import { GoogleGenAI, Type, type Schema } from '@google/genai';

const genai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

app.post('/api/gemini/receipt', async (req, res) => {
  try {
    const { base64, mimeType } = req.body;
    if (!base64) {
      return res.status(400).json({ error: 'base64 image data missing' });
    }

    const responseSchema: Schema = {
      type: Type.OBJECT,
      properties: {
        isReceipt: {
          type: Type.BOOLEAN,
          description: 'Set to true if the document is a receipt, invoice, payment screenshot (Dr/Cr), or bank notification. False otherwise.',
        },
        title: {
          type: Type.STRING,
          description: 'A short title. For receipts, use the vendor. For Dr/Cr screenshots, use the transaction party (e.g. "To John", "From Bank", "GPay to Merchant").',
        },
        amount: {
          type: Type.NUMBER,
          description: 'The final numeric amount. If it is a Debit (Dr), keep it positive. If it is a Credit (Cr), the user will manage it, so just provide the absolute value.',
        },
        category: {
          type: Type.STRING,
          description: 'The category. For payment screenshots, guess based on context (e.g. Transfers, Salary, Bill Payment).',
        },
        items: {
          type: Type.ARRAY,
          description: 'A list of line-items. for screenshots with single amounts, create one item representing the whole transaction.',
          items: {
            type: Type.OBJECT,
            properties: {
              name: {
                type: Type.STRING,
                description: 'The name or description of the line item',
              },
              price: {
                type: Type.NUMBER,
                description: 'The price or cost of this specific line item',
              },
            },
            required: ['name', 'price'],
          },
        },
      },
      required: ['isReceipt', 'title', 'amount', 'category', 'items']
    };

    const response = await genai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [
        {
          role: 'user',
          parts: [
            { text: 'Analyze this document. First, determine if it is a receipt, invoice, payment screenshot (GPay/PhonePe), Bank Dr/Cr notification, or payment-related document. If it is NOT, set "isReceipt" to false. If it IS, set "isReceipt" to true and output structured JSON. Identify the main amount and categorize it. If it is a payment screenshot (like GPay), use the recipient/sender name as the title.' },
            {
              inlineData: {
                data: base64,
                mimeType: mimeType || 'image/jpeg',
              }
            }
          ]
        }
      ],
      config: {
        responseMimeType: 'application/json',
        responseSchema: responseSchema,
      }
    });

    const outputText = response.text || '{}';
    const json = JSON.parse(outputText);
    return res.json(json);
  } catch (e: any) {
    console.error('Gemini error:', e);
    return res.status(500).json({ error: e.message || 'Error processing receipt' });
  }
});

app.get('/api/vaults/:vaultId/ai-insights', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const userId = String(req.query.userId || '');

    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const membership = await prisma.userVault.findFirst({
      where: { userId, vaultId },
      include: { vault: { select: { name: true } } }
    });

    if (!membership) {
      return res.status(403).json({ error: 'Not allowed to view this space' });
    }

    const transactions = await prisma.transaction.findMany({
      where: { vaultId },
      orderBy: { createdAt: 'desc' },
      take: 40,
      include: { creator: { select: { name: true } } }
    });

    if (transactions.length === 0) {
      return res.json({ insights: "No transactions found to analyze yet. Start adding some to get insights!" });
    }

    const txSummary = transactions.map(t => ({
      title: t.title,
      amount: t.amount,
      type: (t as any).type || 'DR',
      category: t.category,
      user: t.creator?.name || 'Unknown',
      date: t.createdAt.toISOString().split('T')[0]
    }));

    const response = await genai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [{
        role: 'user',
        parts: [{
          text: `You are a financial analyst AI for a shared money tracking app. 
          Analyze these recent expenses for a space called "${membership.vault.name}". 
          All amounts are in Indian Rupees (₹). ALWAYS use the ₹ symbol, never use $ or USD.
          
          Data (JSON): ${JSON.stringify(txSummary)}
          
          Provide a concise, conversational summary (max 200 words). 
          Include:
          1. A quick breakdown of who is driving the spending.
          2. The top spending categories.
          3. One actionable tip to save money or a funny observation about the specific spending pattern.
          Use emojis and keep it professional yet friendly. Use markdown for formatting.`
        }]
      }]
    });

    const insights = response.text || "I couldn't generate insights at this moment.";
    res.json({ insights });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/vaults/:vaultId/chat', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const { userId, message, history } = req.body;

    if (!userId || !message) return res.status(400).json({ error: 'userId and message are required' });

    const membership = await prisma.userVault.findFirst({
      where: { userId, vaultId },
      include: { vault: { select: { name: true } }, user: { select: { name: true } } }
    });
    if (!membership) return res.status(403).json({ error: 'Not allowed' });

    const transactions = await prisma.transaction.findMany({
      where: { vaultId },
      orderBy: { createdAt: 'desc' },
      take: 100,
      include: { creator: { select: { name: true, email: true } } }
    });

    const members = await prisma.userVault.findMany({
      where: { vaultId },
      include: { user: { select: { name: true, email: true } } }
    });

    const txSummary = transactions.map(t => ({
      title: t.title,
      amount: t.amount,
      type: (t as any).type || 'DR',
      category: t.category,
      by: t.creator?.name || t.creator?.email || 'Unknown',
      date: t.createdAt.toISOString().split('T')[0],
      splitWith: (t as any).splitWith || []
    }));

    const memberNames = members.map(m => m.user?.name || m.user?.email || 'Unknown');
    const systemPrompt = `You are a smart financial assistant for a shared expense tracking space called "${membership.vault.name}".
The current user is: ${membership.user?.name || 'User'}.
Space members: ${memberNames.join(', ')}.
All amounts are in Indian Rupees (₹). ALWAYS use the ₹ symbol.
Today's date: ${new Date().toISOString().split('T')[0]}.

Transaction data (last 100 transactions):
${JSON.stringify(txSummary, null, 2)}

Answer the user's questions concisely and accurately based on this data. Use markdown formatting and emojis to make responses friendly. If you make calculations, show the math briefly. Keep answers under 150 words.`;

    const chatHistory = (history || []).map((msg: { role: string; text: string }) => ({
      role: msg.role === 'user' ? 'user' : 'model',
      parts: [{ text: msg.text }]
    }));

    const chat = genai.chats.create({
      model: 'gemini-2.5-flash',
      history: [
        { role: 'user', parts: [{ text: systemPrompt }] },
        { role: 'model', parts: [{ text: `Got it! I'm your financial assistant for the "${membership.vault.name}" space. Ask me anything about your expenses — I have access to your transaction history and will answer in ₹. 💰` }] },
        ...chatHistory
      ]
    });

    const response = await chat.sendMessage({ message });
    res.json({ reply: response.text });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/gemini/parse-text', async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Text is required' });

    const responseSchema: Schema = {
      type: Type.OBJECT,
      properties: {
        title: { type: Type.STRING },
        amount: { type: Type.NUMBER },
        type: { type: Type.STRING, description: 'DR for spending, CR for income' },
        category: { type: Type.STRING }
      },
      required: ['title', 'amount', 'type', 'category']
    };

    const response = await genai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [{ role: 'user', parts: [{ text: `Parse this transaction: "${text}". Return JSON with: title, amount (number), type (DR/CR), category.` }] }],
      config: { responseMimeType: 'application/json', responseSchema }
    });

    const parsed = JSON.parse(response.text || '{}');
    res.json(parsed);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/vaults/:vaultId/forecast', async (req, res) => {
  try {
    const vaultId = req.params.vaultId;
    const userId = String(req.query.userId || '');

    const membership = await prisma.userVault.findFirst({ where: { userId, vaultId } });
    if (!membership) return res.status(403).json({ error: 'Not allowed' });

    const transactions = await prisma.transaction.findMany({
      where: { vaultId },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });

    if (transactions.length < 5) {
      return res.json({ forecast: "Need more transaction history (at least 5 items) to generate a reliable forecast." });
    }

    const dataString = JSON.stringify(transactions.map(t => ({
      amt: t.amount,
      type: (t as any).type || 'DR',
      date: t.createdAt.toISOString().split('T')[0],
      title: t.title
    })));

    const response = await genai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [{
        role: 'user', parts: [{
          text: `Analyze these expenses and predict the next month's spending. 
      All amounts are in Indian Rupees (₹). ALWAYS use the ₹ symbol, never use $ or USD.
      Current date: ${new Date().toISOString()}.
      History: ${dataString}.
      Provide a breakdown of predicted total spend (in ₹), recurring expenses to watch out for, and a 1-sentence budget warning. Keep it under 150 words. Use markdown and emojis.` }]
      }]
    });

    res.json({ forecast: response.text });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[Antigravity] Edge Server running on http://localhost:${PORT}`);
});
