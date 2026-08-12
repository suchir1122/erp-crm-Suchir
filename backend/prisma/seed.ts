import { PrismaClient, Role } from '@prisma/client';
import bcrypt from 'bcryptjs';
const prisma=new PrismaClient();
async function main(){const passwordHash=await bcrypt.hash('Password123!',12);for(const [name,email,role] of [['Admin','admin@erp.local',Role.ADMIN],['Sales','sales@erp.local',Role.SALES],['Warehouse','warehouse@erp.local',Role.WAREHOUSE],['Accounts','accounts@erp.local',Role.ACCOUNTS]] as const){await prisma.user.upsert({where:{email},update:{},create:{name,email,role,passwordHash}});}console.log('Seeded users');}main().finally(()=>prisma.$disconnect());
