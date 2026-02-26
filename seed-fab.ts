import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function main() {
  await prisma.user.upsert({
    where: { id: 'user-demo' },
    update: {},
    create: { id: 'user-demo', email: 'demo-fab@example.com', name: 'Demo Fab User' }
  });
  console.log('Upserted user-demo');
}
main().catch(e => console.error(e)).finally(() => prisma.$disconnect());
