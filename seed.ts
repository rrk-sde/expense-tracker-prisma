import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function main() {
  const user = await prisma.user.create({ data: { email: 'live@example.com', name: 'Live User' }});
  const vault = await prisma.vault.create({ data: { id: 'vault-777', name: 'Live Production Budget' }});
  await prisma.userVault.create({ data: { userId: user.id, vaultId: vault.id, role: 'OWNER' }});
  console.log('Seeded User & Vault for Live Aiven Instance');
}
main().catch(e => console.error(e)).finally(() => prisma.$disconnect());
