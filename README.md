# Nexus ERP CRM — Full Stack Case Study

Mini ERP + CRM Operations Portal for a wholesale/distribution company.

## Case-study coverage

- JWT authentication with bcrypt password hashing
- RBAC: Admin, Sales, Warehouse, Accounts
- Customer CRM: add, edit, search, detail, status, GST, follow-up date, follow-up notes
- Product management: SKU, category, unit price, stock, minimum-stock alert, warehouse location, image URL
- Inventory: IN/OUT stock movements, reason, creator and timestamp, no-negative-stock rule
- Sales challans: customer, multiple products, quantities, automatic challan number, Draft/Confirmed/Cancelled
- Product snapshot stored on challan items
- Confirmed challans deduct stock atomically and create OUT movements
- Insufficient stock returns a proper error and rolls back the transaction
- REST API validation, status codes, error responses, pagination and search/filter
- Responsive admin-style React UI
- Environment variable examples
- Postman collection
- Docker setup

## Architecture

React + TypeScript frontend → Express + TypeScript REST API → Prisma → PostgreSQL.

The repository is purpose-built for the supplied assignment and uses common ERP/CRM architecture patterns.

## Local setup

### Backend

```bash
cd backend
npm install
cp .env.example .env
npm run prisma:generate
npx prisma migrate dev --name init
npm run prisma:seed
npm run dev
```

API defaults to `http://localhost:4000`.

### Frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Frontend defaults to `http://localhost:5173`.

## Demo credentials

All demo users use `Password123!`:

- admin@erp.local — ADMIN
- sales@erp.local — SALES
- warehouse@erp.local — WAREHOUSE
- accounts@erp.local — ACCOUNTS

## Environment variables

Backend: `DATABASE_URL`, `JWT_SECRET`, `PORT`, `CORS_ORIGIN`.

Frontend: `VITE_API_URL`.

Never commit real `.env` files or production secrets.

## Main API endpoints

- `POST /auth/login`
- `GET /auth/me`
- `GET /dashboard/summary`
- `GET/POST/PUT /customers`
- `GET /customers/:id`
- `POST /customers/:id/followups`
- `GET/POST/PUT /products`
- `GET /products/:id/stock-movements`
- `POST /products/:id/stock`
- `GET /stock-movements`
- `GET /challans`
- `GET /challans/:id`
- `POST /challans`
- `PUT /challans/:id`
- `POST /challans/:id/confirm`
- `POST /challans/:id/cancel`

## Deployment

Recommended free deployment: frontend on Vercel/Netlify, backend on Render/Railway/Fly.io, and database on Neon/Supabase/Render Postgres. AWS is optional for this assignment.

## Verification flow

1. Login as Sales.
2. Create a customer.
3. Login as Admin and create a product with opening stock.
4. Confirm the opening stock appears in Stock Movements.
5. Create a Sales Challan as Sales and save it as Draft.
6. Confirm the challan.
7. Verify stock decreases and an OUT movement is created.
8. Try to confirm a challan with more stock than available; the API must reject it without partially changing stock.
9. Login as Warehouse and verify inventory actions are available while admin-only product creation is blocked.
10. Login as Accounts and verify read-only access to operational data.

## Known limitations

AWS deployment, S3 upload, invoice PDF export and GitHub Actions deployment are optional bonus extensions; the required core workflow is implemented first.
