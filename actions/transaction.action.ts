import { PrismaClient } from '@prisma/client';
import Pusher from 'pusher';

const prisma = new PrismaClient();

// In a robust distributed system, these instances are typically singletons
// managed via Dependency Injection or module caching across Cloudflare/Edge workers.
const pusher = new Pusher({
    appId: process.env.PUSHER_APP_ID!,
    key: process.env.PUSHER_KEY!,
    secret: process.env.PUSHER_SECRET!,
    cluster: process.env.PUSHER_CLUSTER!,
    useTLS: true,
});

export interface CreateTransactionDTO {
    title: string;
    amount: number;
    category?: string;
    vaultId: string;
    creatorId: string;
}

/**
 * Antigravity Action: onCreateTransaction
 * Real-time event-driven transaction creation
 */
export async function onCreateTransaction(data: CreateTransactionDTO) {
    try {
        // 1. Transaction Atomic Creation
        const transaction = await prisma.transaction.create({
            data: {
                title: data.title,
                amount: data.amount,
                category: data.category,
                vaultId: data.vaultId,
                creatorId: data.creatorId,
            },
            include: {
                creator: { select: { id: true, name: true } },
            }
        });

        // 2. Compute "Spending Velocity" at the edge
        // Computes analytics asynchronously to prevent blocking the transaction save
        const velocityResult = await prisma.transaction.aggregate({
            where: {
                vaultId: data.vaultId,
                createdAt: {
                    gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Last 7 days
                }
            },
            _sum: { amount: true },
            _count: true
        });

        const spendingVelocity = {
            totalAmount7d: velocityResult._sum.amount || 0,
            count7d: velocityResult._count || 0
        };

        // 3. Trigger Real-time Events via Pusher
        const channelName = `presence-vault-${data.vaultId}`;

        // Broadcast the new transaction and the updated analytics concurrently
        await Promise.all([
            pusher.trigger(channelName, 'transaction.created', {
                transaction,
            }),
            pusher.trigger(channelName, 'analytics.velocity_updated', {
                spendingVelocity,
            })
        ]);

        return { success: true, transaction, spendingVelocity };

    } catch (error) {
        console.error('[Antigravity] onCreateTransaction Error:', error);
        throw new Error('Failed to process transaction and broadcast real-time events.');
    }
}
