const path = require('path');
const express = require('express');
const session = require('express-session');
const compression = require('compression');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const { z } = require('zod');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, 'public');

app.set('trust proxy', 1);
app.use(compression());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  name: 'prn.sid',
  secret: process.env.SESSION_SECRET || 'change-this-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000*60*60*24*7 }
}));
app.use(express.static(PUBLIC_DIR, { maxAge: '1h' }));

function isAdmin(req,res,next){ if(req.session?.admin) return next(); res.status(401).json({error:'Admin login required'}); }
function isUser(req,res,next){ if(req.session?.userId) return next(); res.status(401).json({error:'Please sign in first'}); }

const defaultServices = [
  { platform:'Instagram', name:'Followers', description:'Add followers to your public Instagram profile. Drops may happen from 0–30% depending on platform review.', icon:'users', packages:[['1K Followers','₹399'],['5K Followers','₹1499'],['10K Followers','₹2499']] },
  { platform:'Instagram', name:'Likes', description:'Add likes to your public Instagram post or reel. Results and retention may vary.', icon:'heart', packages:[['500 Likes','₹199'],['2K Likes','₹699'],['5K Likes','₹1299']] },
  { platform:'Instagram', name:'Comments', description:'Add comments to your public Instagram post or reel. Abusive or unsafe content is not accepted.', icon:'chat', packages:[['50 Comments','₹299'],['200 Comments','₹999'],['500 Comments','₹1999']] },
  { platform:'Facebook', name:'Page Followers', description:'Add followers to your public Facebook page. Drops may happen from 0–30%.', icon:'users', packages:[['1K Followers','₹399'],['5K Followers','₹1499'],['10K Followers','₹2499']] },
  { platform:'Facebook', name:'Post Likes', description:'Add likes to your public Facebook post. Results may vary.', icon:'heart', packages:[['500 Likes','₹199'],['2K Likes','₹699'],['5K Likes','₹1299']] },
  { platform:'Facebook', name:'Comments', description:'Add comments to your public Facebook post. Unsafe content is not accepted.', icon:'chat', packages:[['50 Comments','₹299'],['200 Comments','₹999'],['500 Comments','₹1999']] },
  { platform:'YouTube', name:'Subscribers', description:'Add subscribers to your public YouTube channel. Monetization is not guaranteed.', icon:'play', packages:[['500 Subscribers','₹599'],['2K Subscribers','₹1999'],['5K Subscribers','₹3999']] },
  { platform:'YouTube', name:'Views', description:'Add views/reach to your public YouTube video. Watch time, ranking and revenue are not guaranteed.', icon:'eye', packages:[['1K Views','₹699'],['5K Views','₹1999'],['10K Views','₹4999']] },
  { platform:'YouTube', name:'Likes', description:'Add likes to your public YouTube video. Results may vary.', icon:'heart', packages:[['500 Likes','₹249'],['2K Likes','₹799'],['5K Likes','₹1699']] }
];

async function seedServicesIfEmpty(){
  const count = await prisma.service.count();
  if(count > 0) return;
  for(let i=0;i<defaultServices.length;i++){
    const s = defaultServices[i];
    await prisma.service.create({
      data:{ platform:s.platform, name:s.name, description:s.description, icon:s.icon, sortOrder:i,
        packages:{ create:s.packages.map((p,idx)=>({name:p[0], price:p[1], sortOrder:idx})) } }
    });
  }
}

const signupSchema = z.object({ name:z.string().trim().min(2).max(80), email:z.string().trim().email().max(120), password:z.string().min(6).max(100) });
const loginSchema = z.object({ email:z.string().trim().email(), password:z.string().min(1) });
const orderSchema = z.object({
  name:z.string().trim().min(2,'Please enter your name').max(80),
  platform:z.string().trim().min(2).max(50),
  service:z.string().trim().min(1).max(100),
  packageName:z.string().trim().min(1).max(100),
  price:z.string().trim().max(30).optional().default(''),
  accountLink:z.string().trim().min(1,'Please paste your public profile/post/channel link').max(500),
  notes:z.string().trim().max(500).optional().nullable(),
  acceptedDisclaimer:z.boolean().optional().default(true)
});

app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/auth/signup', async(req,res,next)=>{ try{
  const data = signupSchema.parse(req.body||{});
  const email = data.email.toLowerCase();
  if(await prisma.user.findUnique({where:{email}})) return res.status(400).json({error:'Account already exists. Please sign in.'});
  const user = await prisma.user.create({ data:{name:data.name,email,passwordHash:await bcrypt.hash(data.password,12)}, select:{id:true,name:true,email:true} });
  req.session.userId = user.id; res.json({user});
}catch(e){next(e)}});
app.post('/api/auth/login', async(req,res,next)=>{ try{
  const data = loginSchema.parse(req.body||{});
  const user = await prisma.user.findUnique({where:{email:data.email.toLowerCase()}});
  if(!user || !(await bcrypt.compare(data.password,user.passwordHash))) return res.status(401).json({error:'Invalid email or password'});
  req.session.userId = user.id; res.json({user:{id:user.id,name:user.name,email:user.email}});
}catch(e){next(e)}});
app.post('/api/auth/logout',(req,res)=>{ req.session.userId=null; res.json({ok:true}); });
app.get('/api/auth/me', async(req,res,next)=>{ try{
  if(!req.session.userId) return res.json({user:null});
  const user = await prisma.user.findUnique({where:{id:req.session.userId}, select:{id:true,name:true,email:true}});
  res.json({user});
}catch(e){next(e)}});

app.get('/api/services', async(req,res,next)=>{ try{
  const services = await prisma.service.findMany({ where:{active:true}, orderBy:[{sortOrder:'asc'},{createdAt:'asc'}], include:{packages:{where:{active:true}, orderBy:[{sortOrder:'asc'},{createdAt:'asc'}]}}});
  res.json({services});
}catch(e){next(e)}});

app.post('/api/orders', async(req,res,next)=>{ try{
  const data = orderSchema.parse(req.body||{});
  let user = null;
  if(req.session.userId) user = await prisma.user.findUnique({where:{id:req.session.userId}, select:{id:true,name:true,email:true}});
  const id = 'PRN-' + Date.now().toString().slice(-8);
  const order = await prisma.order.create({ data:{
    id, userId:user?.id || null, name:user?.name || data.name, email:user?.email || null,
    platform:data.platform, service:data.service, packageName:data.packageName, price:data.price || '',
    accountLink:data.accountLink, notes:data.notes || '', acceptedDisclaimer:!!data.acceptedDisclaimer
  }});
  res.json({order});
}catch(e){next(e)}});

app.get('/api/orders/:id', async(req,res,next)=>{ try{
  const order = await prisma.order.findUnique({where:{id:req.params.id}});
  if(!order) return res.status(404).json({error:'No order found with this ID'});
  if(order.userId && req.session.userId && order.userId !== req.session.userId) return res.status(403).json({error:'This order belongs to another account'});
  res.json({order});
}catch(e){next(e)}});
app.get('/api/my/orders', isUser, async(req,res,next)=>{ try{
  const orders = await prisma.order.findMany({where:{userId:req.session.userId}, orderBy:{createdAt:'desc'}});
  res.json({orders});
}catch(e){next(e)}});

app.post('/api/admin/login',(req,res)=>{
  if(String(req.body.phone||'').trim()===(process.env.ADMIN_PHONE||'7897671348') && String(req.body.password||'')===(process.env.ADMIN_PASSWORD||'yashbajpa')){
    req.session.admin=true; return res.json({ok:true});
  }
  res.status(401).json({error:'Invalid admin login'});
});
app.post('/api/admin/logout', isAdmin, (req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/orders', isAdmin, async(req,res,next)=>{ try{ res.json({orders:await prisma.order.findMany({orderBy:{createdAt:'desc'}, include:{user:{select:{name:true,email:true}}}})}); }catch(e){next(e)}});
app.patch('/api/admin/orders/:id', isAdmin, async(req,res,next)=>{ try{
  const status=String(req.body.status||'').trim(); if(!['Pending','Processing','Completed','Cancelled'].includes(status)) return res.status(400).json({error:'Invalid status'});
  res.json({order:await prisma.order.update({where:{id:req.params.id},data:{status}})});
}catch(e){next(e)}});

app.get('/api/admin/services', isAdmin, async(req,res,next)=>{ try{
  res.json({services:await prisma.service.findMany({orderBy:[{sortOrder:'asc'},{createdAt:'asc'}], include:{packages:{orderBy:[{sortOrder:'asc'},{createdAt:'asc'}]}}})});
}catch(e){next(e)}});
app.post('/api/admin/services', isAdmin, async(req,res,next)=>{ try{
  res.json({service:await prisma.service.create({data:{platform:String(req.body.platform||'Instagram').trim(),name:String(req.body.name||'New Service').trim(),description:String(req.body.description||'Results may vary.').trim(),icon:String(req.body.icon||'spark').trim(),active:req.body.active!==false,packages:{create:[{name:'1K Followers',price:'₹399'}]}},include:{packages:true}})});
}catch(e){next(e)}});
app.patch('/api/admin/services/:id', isAdmin, async(req,res,next)=>{ try{
  res.json({service:await prisma.service.update({where:{id:req.params.id},data:{platform:String(req.body.platform||'').trim(),name:String(req.body.name||'').trim(),description:String(req.body.description||'').trim(),icon:String(req.body.icon||'spark').trim(),active:req.body.active!==false},include:{packages:true}})});
}catch(e){next(e)}});
app.delete('/api/admin/services/:id', isAdmin, async(req,res,next)=>{ try{ await prisma.service.delete({where:{id:req.params.id}}); res.json({ok:true}); }catch(e){next(e)}});
app.post('/api/admin/services/:id/packages', isAdmin, async(req,res,next)=>{ try{ res.json({package:await prisma.package.create({data:{serviceId:req.params.id,name:String(req.body.name||'New Package').trim(),price:String(req.body.price||'₹399').trim()}})}); }catch(e){next(e)}});
app.patch('/api/admin/packages/:id', isAdmin, async(req,res,next)=>{ try{ res.json({package:await prisma.package.update({where:{id:req.params.id},data:{name:String(req.body.name||'').trim(),price:String(req.body.price||'').trim(),active:req.body.active!==false}})}); }catch(e){next(e)}});
app.delete('/api/admin/packages/:id', isAdmin, async(req,res,next)=>{ try{ await prisma.package.delete({where:{id:req.params.id}}); res.json({ok:true}); }catch(e){next(e)}});

app.get('/admin',(req,res)=>res.sendFile(path.join(PUBLIC_DIR,'admin.html')));
app.get('*',(req,res)=>{ if(req.path.startsWith('/api/')) return res.status(404).json({error:'API route not found'}); res.sendFile(path.join(PUBLIC_DIR,'index.html')); });
app.use((err,req,res,next)=>{ if(err?.name==='ZodError'){ const issues=err.issues||err.errors||[]; return res.status(400).json({error:issues.map(x=>`${x.path?.join('.')||'field'}: ${x.message}`).join(', ')||'Invalid details'}); } if(err?.code==='P2002') return res.status(400).json({error:'Already exists'}); console.error(err); res.status(500).json({error:'Server error'}); });
seedServicesIfEmpty().then(()=>app.listen(PORT,()=>console.log('The PR Network running on '+PORT))).catch(e=>{console.error(e);process.exit(1)});
