import 'dotenv/config';
import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient, Role, MovementType, ChallanStatus, CustomerStatus, CustomerType } from '@prisma/client';
import { z } from 'zod';

const prisma = new PrismaClient();
const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const port = Number(process.env.PORT || 4000);

type AuthRequest = Request & {
  user?: { id: string; role: Role; name: string; email: string };
};

app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '2mb' }));

const sign = (id: string) => jwt.sign({ sub: id }, JWT_SECRET, { expiresIn: '8h' });
const safeUser = (u: any) => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const pagination = (req: Request) => ({
  page: Math.max(1, Number(req.query.page || 1)),
  limit: Math.min(100, Math.max(1, Number(req.query.limit || 10)))
});
const dateOrUndefined = (value?: string) => value ? new Date(value) : undefined;

const auth = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }
    const payload = jwt.verify(header.slice(7), JWT_SECRET) as jwt.JwtPayload;
    const user = await prisma.user.findUnique({
      where: { id: String(payload.sub) },
      select: { id: true, role: true, name: true, email: true }
    });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid authentication token' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

const allow = (...roles: Role[]) => (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, message: 'Insufficient permissions' });
  }
  next();
};

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'erp-crm-api' }));

app.post('/auth/login', async (req, res) => {
  const parsed = z.object({ email: z.string().email(), password: z.string().min(1) }).safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Invalid login data', errors: parsed.error.flatten() });
  const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase() } });
  if (!user || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) {
    return res.status(401).json({ success: false, message: 'Invalid email or password' });
  }
  res.json({ success: true, token: sign(user.id), user: safeUser(user) });
});

app.get('/auth/me', auth, async (req: AuthRequest, res) => {
  res.json({ success: true, user: safeUser(req.user) });
});

app.get('/dashboard/summary', auth, async (_req, res) => {
  const [customers, products, drafts, confirmed, movements, productRows] = await Promise.all([
    prisma.customer.count(),
    prisma.product.count(),
    prisma.challan.count({ where: { status: ChallanStatus.DRAFT } }),
    prisma.challan.count({ where: { status: ChallanStatus.CONFIRMED } }),
    prisma.stockMovement.findMany({
      take: 8,
      orderBy: { createdAt: 'desc' },
      include: { product: { select: { name: true, sku: true } }, createdBy: { select: { name: true } } }
    }),
    prisma.product.findMany({ select: { currentStock: true, minimumStock: true } })
  ]);
  const lowStock = productRows.filter(p => p.currentStock <= p.minimumStock).length;
  res.json({ success: true, data: { customers, products, lowStock, pendingChallans: drafts, confirmedChallans: confirmed, recentMovements: movements } });
});

const customerSchema = z.object({
  customerName: z.string().min(2),
  mobile: z.string().min(5),
  email: z.string().email().optional().or(z.literal('')),
  businessName: z.string().min(2),
  gstNumber: z.string().optional(),
  customerType: z.nativeEnum(CustomerType),
  address: z.string().min(2),
  status: z.nativeEnum(CustomerStatus).default(CustomerStatus.LEAD),
  followUpDate: z.string().optional(),
  notes: z.string().optional()
});

app.get('/customers', auth, async (req, res) => {
  const { page, limit } = pagination(req);
  const q = String(req.query.search || '');
  const status = req.query.status as CustomerStatus | undefined;
  const where: any = {
    ...(status && Object.values(CustomerStatus).includes(status) ? { status } : {}),
    ...(q ? {
      OR: [
        { customerName: { contains: q, mode: 'insensitive' } },
        { businessName: { contains: q, mode: 'insensitive' } },
        { mobile: { contains: q } },
        { email: { contains: q, mode: 'insensitive' } }
      ]
    } : {})
  };
  const [data, total] = await Promise.all([
    prisma.customer.findMany({
      where,
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: { followUps: { take: 1, orderBy: { createdAt: 'desc' } } }
    }),
    prisma.customer.count({ where })
  ]);
  res.json({ success: true, data, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
});

app.post('/customers', auth, allow(Role.ADMIN, Role.SALES), async (req: AuthRequest, res) => {
  const parsed = customerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed', errors: parsed.error.flatten() });
  const data = parsed.data;
  const customer = await prisma.customer.create({
    data: {
      ...data,
      email: data.email || null,
      followUpDate: dateOrUndefined(data.followUpDate),
      createdById: req.user!.id
    }
  });
  res.status(201).json({ success: true, data: customer });
});

app.get('/customers/:id', auth, async (req, res) => {
  const customer = await prisma.customer.findUnique({
    where: { id: req.params.id },
    include: {
      followUps: { orderBy: { createdAt: 'desc' }, include: { createdBy: { select: { name: true, role: true } } } },
      challans: { orderBy: { createdAt: 'desc' }, take: 10 }
    }
  });
  if (!customer) return res.status(404).json({ success: false, message: 'Customer not found' });
  res.json({ success: true, data: customer });
});

app.put('/customers/:id', auth, allow(Role.ADMIN, Role.SALES), async (req, res) => {
  const parsed = customerSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed', errors: parsed.error.flatten() });
  try {
    const data: any = { ...parsed.data };
    if ('email' in data) data.email = data.email || null;
    if (data.followUpDate) data.followUpDate = new Date(data.followUpDate);
    const customer = await prisma.customer.update({ where: { id: req.params.id }, data });
    res.json({ success: true, data: customer });
  } catch {
    res.status(404).json({ success: false, message: 'Customer not found' });
  }
});

app.post('/customers/:id/followups', auth, allow(Role.ADMIN, Role.SALES), async (req: AuthRequest, res) => {
  const parsed = z.object({ note: z.string().min(1), followUpDate: z.string().optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed' });
  const customer = await prisma.customer.findUnique({ where: { id: req.params.id } });
  if (!customer) return res.status(404).json({ success: false, message: 'Customer not found' });
  const followUp = await prisma.followUp.create({
    data: { customerId: customer.id, note: parsed.data.note, followUpDate: dateOrUndefined(parsed.data.followUpDate), createdById: req.user!.id }
  });
  res.status(201).json({ success: true, data: followUp });
});

const productSchema = z.object({
  name: z.string().min(2),
  sku: z.string().min(1),
  category: z.string().min(1),
  unitPrice: z.coerce.number().nonnegative(),
  currentStock: z.coerce.number().int().nonnegative().default(0),
  minimumStock: z.coerce.number().int().nonnegative().default(0),
  warehouseLocation: z.string().min(1),
  imageUrl: z.string().url().optional().or(z.literal(''))
});

app.get('/products', auth, async (req, res) => {
  const { page, limit } = pagination(req);
  const q = String(req.query.search || '');
  const low = req.query.lowStock === 'true';
  const all = await prisma.product.findMany({
    where: q ? { OR: [
      { name: { contains: q, mode: 'insensitive' } },
      { sku: { contains: q, mode: 'insensitive' } },
      { category: { contains: q, mode: 'insensitive' } }
    ] } : {},
    orderBy: { createdAt: 'desc' }
  });
  const filtered = low ? all.filter(p => p.currentStock <= p.minimumStock) : all;
  res.json({ success: true, data: filtered.slice((page - 1) * limit, page * limit), pagination: { page, limit, total: filtered.length, pages: Math.ceil(filtered.length / limit) } });
});

app.get('/products/:id', auth, async (req, res) => {
  const product = await prisma.product.findUnique({ where: { id: req.params.id }, include: { movements: { orderBy: { createdAt: 'desc' }, take: 50 } } });
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  res.json({ success: true, data: product });
});

app.post('/products', auth, allow(Role.ADMIN), async (req: AuthRequest, res) => {
  const parsed = productSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed', errors: parsed.error.flatten() });
  try {
    const result = await prisma.$transaction(async tx => {
      const product = await tx.product.create({ data: { ...parsed.data, imageUrl: parsed.data.imageUrl || null } });
      if (product.currentStock > 0) {
        await tx.stockMovement.create({
          data: { productId: product.id, quantity: product.currentStock, movementType: MovementType.IN, reason: 'Opening stock', createdById: req.user!.id }
        });
      }
      return product;
    });
    res.status(201).json({ success: true, data: result });
  } catch {
    res.status(409).json({ success: false, message: 'SKU already exists' });
  }
});

app.put('/products/:id', auth, allow(Role.ADMIN), async (req, res) => {
  const parsed = productSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed' });
  try {
    const data: any = { ...parsed.data };
    if (data.imageUrl === '') data.imageUrl = null;
    const product = await prisma.product.update({ where: { id: req.params.id }, data });
    res.json({ success: true, data: product });
  } catch {
    res.status(404).json({ success: false, message: 'Product not found' });
  }
});

app.post('/products/:id/stock', auth, allow(Role.ADMIN, Role.WAREHOUSE), async (req: AuthRequest, res) => {
  const parsed = z.object({ quantity: z.coerce.number().int().positive(), movementType: z.nativeEnum(MovementType), reason: z.string().min(2) }).safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed', errors: parsed.error.flatten() });
  try {
    const result = await prisma.$transaction(async tx => {
      const product = await tx.product.findUnique({ where: { id: req.params.id } });
      if (!product) throw new Error('NOT_FOUND');
      if (parsed.data.movementType === MovementType.OUT && product.currentStock < parsed.data.quantity) throw new Error('INSUFFICIENT');
      const stock = parsed.data.movementType === MovementType.IN ? product.currentStock + parsed.data.quantity : product.currentStock - parsed.data.quantity;
      const updated = await tx.product.update({ where: { id: product.id }, data: { currentStock: stock } });
      const movement = await tx.stockMovement.create({
        data: { productId: product.id, quantity: parsed.data.quantity, movementType: parsed.data.movementType, reason: parsed.data.reason, createdById: req.user!.id }
      });
      return { updated, movement };
    });
    res.json({ success: true, data: result });
  } catch (error: any) {
    if (error.message === 'NOT_FOUND') return res.status(404).json({ success: false, message: 'Product not found' });
    if (error.message === 'INSUFFICIENT') return res.status(409).json({ success: false, message: 'Insufficient stock' });
    res.status(500).json({ success: false, message: 'Could not update stock' });
  }
});

app.get('/products/:id/stock-movements', auth, async (req, res) => {
  const data = await prisma.stockMovement.findMany({ where: { productId: req.params.id }, orderBy: { createdAt: 'desc' }, include: { createdBy: { select: { name: true, role: true } } } });
  res.json({ success: true, data });
});

app.get('/stock-movements', auth, async (req, res) => {
  const { page, limit } = pagination(req);
  const [data, total] = await Promise.all([
    prisma.stockMovement.findMany({ skip: (page - 1) * limit, take: limit, orderBy: { createdAt: 'desc' }, include: { product: true, createdBy: { select: { name: true, role: true } } } }),
    prisma.stockMovement.count()
  ]);
  res.json({ success: true, data, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
});

const challanSchema = z.object({
  customerId: z.string().min(1),
  items: z.array(z.object({ productId: z.string().min(1), quantity: z.coerce.number().int().positive() })).min(1)
});

app.get('/challans', auth, async (req, res) => {
  const { page, limit } = pagination(req);
  const status = req.query.status as ChallanStatus | undefined;
  const where = status && Object.values(ChallanStatus).includes(status) ? { status } : {};
  const [data, total] = await Promise.all([
    prisma.challan.findMany({ where, skip: (page - 1) * limit, take: limit, include: { customer: true, createdBy: { select: { name: true, role: true } }, items: true }, orderBy: { createdAt: 'desc' } }),
    prisma.challan.count({ where })
  ]);
  res.json({ success: true, data, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
});

app.get('/challans/:id', auth, async (req, res) => {
  const challan = await prisma.challan.findUnique({ where: { id: req.params.id }, include: { customer: true, createdBy: { select: { name: true, role: true } }, items: true } });
  if (!challan) return res.status(404).json({ success: false, message: 'Challan not found' });
  res.json({ success: true, data: challan });
});

const buildChallanItems = async (tx: any, items: Array<{ productId: string; quantity: number }>) => {
  const products = await tx.product.findMany({ where: { id: { in: items.map(item => item.productId) } } });
  const map = new Map(products.map((product: any) => [product.id, product]));
  return items.map(item => {
    const product = map.get(item.productId) as any;
    if (!product) throw new Error('PRODUCT');
    return { ...item, productName: product.name, sku: product.sku, unitPrice: product.unitPrice };
  });
};

app.post('/challans', auth, allow(Role.ADMIN, Role.SALES), async (req: AuthRequest, res: Response) => {
  const parsed = challanSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed', errors: parsed.error.flatten() });
  try {
    const customer = await prisma.customer.findUnique({ where: { id: parsed.data.customerId } });
    if (!customer) return res.status(404).json({ success: false, message: 'Customer not found' });
    const items = await buildChallanItems(prisma, parsed.data.items);
    const number = `CH-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(Date.now()).slice(-6)}`;
    const challan = await prisma.challan.create({
      data: { challanNumber: number, customerId: customer.id, createdById: req.user!.id, totalQuantity: items.reduce((sum: number, item: any) => sum + item.quantity, 0), items: { create: items } },
      include: { items: true, customer: true }
    });
    res.status(201).json({ success: true, data: challan });
  } catch (error: any) {
    if (error.message === 'PRODUCT') return res.status(422).json({ success: false, message: 'One or more products are invalid' });
    res.status(500).json({ success: false, message: 'Could not create challan' });
  }
});

app.put('/challans/:id', auth, allow(Role.ADMIN, Role.SALES), async (req, res) => {
  const parsed = challanSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).json({ success: false, message: 'Validation failed', errors: parsed.error.flatten() });
  try {
    const updated = await prisma.$transaction(async tx => {
      const challan = await tx.challan.findUnique({ where: { id: req.params.id } });
      if (!challan) throw new Error('NOT_FOUND');
      if (challan.status !== ChallanStatus.DRAFT) throw new Error('STATUS');
      const customer = await tx.customer.findUnique({ where: { id: parsed.data.customerId } });
      if (!customer) throw new Error('CUSTOMER');
      const items = await buildChallanItems(tx, parsed.data.items);
      await tx.challanItem.deleteMany({ where: { challanId: challan.id } });
      return tx.challan.update({
        where: { id: challan.id },
        data: { customerId: customer.id, totalQuantity: items.reduce((sum: number, item: any) => sum + item.quantity, 0), items: { create: items } },
        include: { items: true, customer: true }
      });
    });
    res.json({ success: true, data: updated });
  } catch (error: any) {
    if (error.message === 'NOT_FOUND') return res.status(404).json({ success: false, message: 'Challan not found' });
    if (error.message === 'STATUS') return res.status(409).json({ success: false, message: 'Only draft challans can be edited' });
    if (error.message === 'CUSTOMER') return res.status(404).json({ success: false, message: 'Customer not found' });
    if (error.message === 'PRODUCT') return res.status(422).json({ success: false, message: 'One or more products are invalid' });
    res.status(500).json({ success: false, message: 'Could not update challan' });
  }
});

app.post('/challans/:id/confirm', auth, allow(Role.ADMIN, Role.SALES), async (req: AuthRequest, res: Response) => {
  try {
    const confirmed = await prisma.$transaction(async tx => {
      const challan = await tx.challan.findUnique({ where: { id: req.params.id }, include: { items: true } });
      if (!challan) throw new Error('NOT_FOUND');
      if (challan.status !== ChallanStatus.DRAFT) throw new Error('STATUS');
      const products = await tx.product.findMany({ where: { id: { in: challan.items.map(item => item.productId) } } });
      const map = new Map(products.map(product => [product.id, product]));
      for (const item of challan.items) {
        const product = map.get(item.productId);
        if (!product || product.currentStock < item.quantity) throw new Error(`STOCK:${item.productName}`);
      }
      for (const item of challan.items) {
        const product = map.get(item.productId)!;
        await tx.product.update({ where: { id: product.id }, data: { currentStock: { decrement: item.quantity } } });
        await tx.stockMovement.create({
          data: { productId: product.id, quantity: item.quantity, movementType: MovementType.OUT, reason: `Sales challan ${challan.challanNumber}`, createdById: req.user!.id }
        });
      }
      return tx.challan.update({ where: { id: challan.id }, data: { status: ChallanStatus.CONFIRMED }, include: { items: true, customer: true } });
    });
    res.json({ success: true, data: confirmed });
  } catch (error: any) {
    if (error.message === 'NOT_FOUND') return res.status(404).json({ success: false, message: 'Challan not found' });
    if (error.message === 'STATUS') return res.status(409).json({ success: false, message: 'Only draft challans can be confirmed' });
    if (String(error.message).startsWith('STOCK:')) return res.status(409).json({ success: false, message: `Insufficient stock for ${String(error.message).slice(6)}` });
    res.status(500).json({ success: false, message: 'Could not confirm challan' });
  }
});

app.post('/challans/:id/cancel', auth, allow(Role.ADMIN, Role.SALES), async (req, res) => {
  const challan = await prisma.challan.findUnique({ where: { id: req.params.id } });
  if (!challan) return res.status(404).json({ success: false, message: 'Challan not found' });
  if (challan.status === ChallanStatus.CONFIRMED) return res.status(409).json({ success: false, message: 'Confirmed challans cannot be cancelled' });
  const updated = await prisma.challan.update({ where: { id: challan.id }, data: { status: ChallanStatus.CANCELLED } });
  res.json({ success: true, data: updated });
});

app.use((_req, res) => res.status(404).json({ success: false, message: 'Route not found' }));
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.listen(port, () => console.log(`ERP CRM API running on ${port}`));
