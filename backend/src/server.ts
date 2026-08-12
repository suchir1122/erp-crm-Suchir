import 'dotenv/config';
import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient, Role, MovementType, ChallanStatus } from '@prisma/client';
import { z } from 'zod';

const prisma = new PrismaClient();
const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') ?? true }));
app.use(express.json());

type AuthRequest = Request & { user?: { id: string; role: Role } };
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const sign = (id: string) => jwt.sign({ sub: id }, JWT_SECRET, { expiresIn: '8h' });
const auth = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return res.status(401).json({ success:false, message:'Authentication required' });
    const payload = jwt.verify(header.slice(7), JWT_SECRET) as jwt.JwtPayload;
    const user = await prisma.user.findUnique({ where: { id: String(payload.sub) }, select: { id:true, role:true } });
    if (!user) return res.status(401).json({ success:false, message:'Invalid authentication token' });
    req.user = user; next();
  } catch { return res.status(401).json({ success:false, message:'Invalid or expired token' }); }
};
const allow = (...roles: Role[]) => (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ success:false, message:'Insufficient permissions' });
  next();
};
const safeUser = (u: any) => ({ id:u.id, name:u.name, email:u.email, role:u.role });

app.get('/health', (_req,res)=>res.json({status:'ok'}));
app.post('/auth/login', async (req,res)=>{
  const parsed=z.object({email:z.string().email(),password:z.string().min(1)}).safeParse(req.body);
  if(!parsed.success) return res.status(422).json({success:false,message:'Invalid login data'});
  const user=await prisma.user.findUnique({where:{email:parsed.data.email}});
  if(!user || !(await bcrypt.compare(parsed.data.password,user.passwordHash))) return res.status(401).json({success:false,message:'Invalid email or password'});
  return res.json({success:true,token:sign(user.id),user:safeUser(user)});
});
app.get('/auth/me',auth,async(req:AuthRequest,res)=>{ const u=await prisma.user.findUnique({where:{id:req.user!.id}}); res.json({success:true,user:safeUser(u)}); });

app.get('/customers',auth,async(req,res)=>{ const q=String(req.query.search||''); const page=Math.max(1,Number(req.query.page||1)),limit=Math.min(100,Math.max(1,Number(req.query.limit||10))); const where=q?{OR:[{customerName:{contains:q,mode:'insensitive' as const}},{businessName:{contains:q,mode:'insensitive' as const}},{mobile:{contains:q}}]}:{}; const [data,total]=await Promise.all([prisma.customer.findMany({where,skip:(page-1)*limit,take:limit,orderBy:{createdAt:'desc'}}),prisma.customer.count({where})]); res.json({success:true,data,pagination:{page,limit,total}}); });
app.post('/customers',auth,allow(Role.ADMIN,Role.SALES),async(req:AuthRequest,res)=>{ const p=z.object({customerName:z.string().min(2),mobile:z.string().min(5),email:z.string().email().optional().or(z.literal('')),businessName:z.string().min(2),gstNumber:z.string().optional(),customerType:z.enum(['RETAIL','WHOLESALE','DISTRIBUTOR']),address:z.string().min(2),status:z.enum(['LEAD','ACTIVE','INACTIVE']).default('LEAD'),followUpDate:z.string().optional(),notes:z.string().optional()}).safeParse(req.body); if(!p.success)return res.status(422).json({success:false,message:'Validation failed',errors:p.error.flatten()}); const c=await prisma.customer.create({data:{...p.data,email:p.data.email||null,followUpDate:p.data.followUpDate?new Date(p.data.followUpDate):undefined,createdById:req.user!.id}}); res.status(201).json({success:true,data:c}); });
app.get('/customers/:id',auth,async(req,res)=>{ const c=await prisma.customer.findUnique({where:{id:req.params.id},include:{challans:true}}); if(!c)return res.status(404).json({success:false,message:'Customer not found'}); res.json({success:true,data:c}); });
app.put('/customers/:id',auth,allow(Role.ADMIN,Role.SALES),async(req,res)=>{ try { const c=await prisma.customer.update({where:{id:req.params.id},data:req.body}); res.json({success:true,data:c}); } catch {res.status(404).json({success:false,message:'Customer not found'});} });

app.get('/products',auth,async(req,res)=>{ const q=String(req.query.search||''); const data=await prisma.product.findMany({where:q?{OR:[{name:{contains:q,mode:'insensitive'}},{sku:{contains:q,mode:'insensitive'}}]}:{},orderBy:{createdAt:'desc'}}); res.json({success:true,data}); });
app.post('/products',auth,allow(Role.ADMIN),async(req,res)=>{ const p=z.object({name:z.string().min(2),sku:z.string().min(1),category:z.string().min(1),unitPrice:z.coerce.number().nonnegative(),currentStock:z.coerce.number().int().nonnegative().default(0),minimumStock:z.coerce.number().int().nonnegative().default(0),warehouseLocation:z.string().min(1)}).safeParse(req.body); if(!p.success)return res.status(422).json({success:false,message:'Validation failed',errors:p.error.flatten()}); try {const x=await prisma.product.create({data:p.data}); res.status(201).json({success:true,data:x});}catch{res.status(409).json({success:false,message:'SKU already exists'});} });
app.put('/products/:id',auth,allow(Role.ADMIN),async(req,res)=>{try{const x=await prisma.product.update({where:{id:req.params.id},data:req.body});res.json({success:true,data:x});}catch{res.status(404).json({success:false,message:'Product not found'});}});
app.post('/products/:id/stock',auth,allow(Role.ADMIN,Role.WAREHOUSE),async(req:AuthRequest,res)=>{const p=z.object({quantity:z.coerce.number().int().positive(),movementType:z.enum(['IN','OUT']),reason:z.string().min(2)}).safeParse(req.body);if(!p.success)return res.status(422).json({success:false,message:'Validation failed'});try{const result=await prisma.$transaction(async(tx)=>{const product=await tx.product.findUnique({where:{id:req.params.id}});if(!product)throw new Error('NOT_FOUND');if(p.data.movementType==='OUT'&&product.currentStock<p.data.quantity)throw new Error('INSUFFICIENT');const stock=p.data.movementType==='IN'?product.currentStock+p.data.quantity:product.currentStock-p.data.quantity;const updated=await tx.product.update({where:{id:product.id},data:{currentStock:stock}});const movement=await tx.stockMovement.create({data:{productId:product.id,quantity:p.data.quantity,movementType:p.data.movementType as MovementType,reason:p.data.reason,createdById:req.user!.id}});return {updated,movement};});res.json({success:true,data:result});}catch(e:any){if(e.message==='NOT_FOUND')return res.status(404).json({success:false,message:'Product not found'});if(e.message==='INSUFFICIENT')return res.status(409).json({success:false,message:'Insufficient stock'});throw e;}});
app.get('/products/:id/stock-movements',auth,async(req,res)=>{const data=await prisma.stockMovement.findMany({where:{productId:req.params.id},orderBy:{createdAt:'desc'}});res.json({success:true,data});});

app.get('/challans',auth,async(req,res)=>{const data=await prisma.challan.findMany({include:{customer:true,items:true},orderBy:{createdAt:'desc'}});res.json({success:true,data});});
app.post('/challans',auth,allow(Role.ADMIN,Role.SALES),async(req:AuthRequest,res)=>{const p=z.object({customerId:z.string(),items:z.array(z.object({productId:z.string(),quantity:z.coerce.number().int().positive()})).min(1)}).safeParse(req.body);if(!p.success)return res.status(422).json({success:false,message:'Validation failed'});const number=`CH-${Date.now()}`;const products=await prisma.product.findMany({where:{id:{in:p.data.items.map(i=>i.productId)}}});const map=new Map(products.map(x=>[x.id,x]));const items=p.data.items.map(i=>{const x=map.get(i.productId);if(!x)throw new Error('PRODUCT');return {...i,productName:x.name,sku:x.sku,unitPrice:x.unitPrice};});const c=await prisma.challan.create({data:{challanNumber:number,customerId:p.data.customerId,createdById:req.user!.id,totalQuantity:items.reduce((a,b)=>a+b.quantity,0),items:{create:items}} ,include:{items:true,customer:true}});res.status(201).json({success:true,data:c});});
app.post('/challans/:id/confirm',auth,allow(Role.ADMIN,Role.SALES),async(req,res)=>{try{const c=await prisma.$transaction(async(tx)=>{const challan=await tx.challan.findUnique({where:{id:req.params.id},include:{items:true}});if(!challan)throw new Error('NOT_FOUND');if(challan.status!==ChallanStatus.DRAFT)throw new Error('STATUS');const ids=challan.items.map(i=>i.productId);const products=await tx.product.findMany({where:{id:{in:ids}}});const map=new Map(products.map(p=>[p.id,p]));for(const i of challan.items){const p=map.get(i.productId);if(!p||p.currentStock<i.quantity)throw new Error(`STOCK:${i.productName}`);}for(const i of challan.items){const p=map.get(i.productId)!;await tx.product.update({where:{id:p.id},data:{currentStock:{decrement:i.quantity}}});await tx.stockMovement.create({data:{productId:p.id,quantity:i.quantity,movementType:MovementType.OUT,reason:`Sales challan ${challan.challanNumber}`}});}return tx.challan.update({where:{id:challan.id},data:{status:ChallanStatus.CONFIRMED},include:{items:true,customer:true}});});res.json({success:true,data:c});}catch(e:any){if(e.message==='NOT_FOUND')return res.status(404).json({success:false,message:'Challan not found'});if(e.message==='STATUS')return res.status(409).json({success:false,message:'Only draft challans can be confirmed'});if(e.message.startsWith('STOCK:'))return res.status(409).json({success:false,message:`Insufficient stock for ${e.message.slice(6)}`});throw e;}});
app.post('/challans/:id/cancel',auth,allow(Role.ADMIN,Role.SALES),async(req,res)=>{try{const c=await prisma.challan.update({where:{id:req.params.id},data:{status:ChallanStatus.CANCELLED}});res.json({success:true,data:c});}catch{res.status(404).json({success:false,message:'Challan not found'});}});

app.use((err:any,_req:Request,res:Response,_next:NextFunction)=>{console.error(err);res.status(500).json({success:false,message:'Internal server error'});});
const port=Number(process.env.PORT||4000);app.listen(port,()=>console.log(`API running on ${port}`));
