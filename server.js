
// server.js - Node + Express minimal com JWT auth e armazenamento em arquivo JSON
// Versão corrigida: trata arquivos JSON vazios/corrompidos ao ler products/users.
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const JWT_SECRET = process.env.JWT_SECRET || 'troque_essa_chave_para_producao';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Default sample objects
const SAMPLE_PRODUCTS = [
  {id:1,name:"Espelho Oval de Parede Com Led Quente/Frio",price:"R$ 89,90",category:"cozinha",image:"/assets/produtos/espelho01.jpg",tag:"Mais vendido",url:"https://s.shopee.com.br/2B5oQoJyeQ"}
];

const SAMPLE_USERS = async () => {
  const hash = await bcrypt.hash('admin123', 10);
  return [{username:'admin', passwordHash: hash}];
};

// util: ensure data dir and files exist (and not empty/corrupt)
async function ensureFiles(){
  try{
    await fs.mkdir(DATA_DIR, { recursive: true });

    // products file
    try {
      const st = await fs.stat(PRODUCTS_FILE);
      if (!st.isFile() || st.size === 0) throw new Error('empty');
      // try parse to ensure valid JSON
      const raw = await fs.readFile(PRODUCTS_FILE, 'utf8');
      JSON.parse(raw);
    } catch (e) {
      // create/reset with sample products
      await fs.writeFile(PRODUCTS_FILE, JSON.stringify(SAMPLE_PRODUCTS, null, 2));
      console.log('products.json criado/recuperado com amostra.');
    }

    // users file
    try {
      const st2 = await fs.stat(USERS_FILE);
      if (!st2.isFile() || st2.size === 0) throw new Error('empty');
      const raw2 = await fs.readFile(USERS_FILE, 'utf8');
      JSON.parse(raw2);
    } catch (e) {
      const users = await SAMPLE_USERS();
      await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
      console.log('users.json criado com usuário admin (senha: admin123).');
    }

  }catch(err){
    console.error('Erro garantindo arquivos:', err);
    process.exit(1);
  }
}

async function readProducts(){
  try{
    const raw = await fs.readFile(PRODUCTS_FILE, 'utf8');
    if(!raw) throw new Error('empty');
    return JSON.parse(raw);
  }catch(e){
    console.warn('products.json inválido ou vazio — recriando com sample. (', e.message, ')');
    await fs.writeFile(PRODUCTS_FILE, JSON.stringify(SAMPLE_PRODUCTS, null, 2));
    return SAMPLE_PRODUCTS;
  }
}
async function writeProducts(arr){
  await fs.writeFile(PRODUCTS_FILE, JSON.stringify(arr, null, 2));
}

// Auth middleware
function authenticateToken(req, res, next){
  const auth = req.headers['authorization'];
  if(!auth) return res.status(401).json({error:'Token faltando'});
  const parts = auth.split(' ');
  if(parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({error:'Formato inválido'});
  const token = parts[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  }catch(e){
    return res.status(401).json({error:'Token inválido'});
  }
}

// Login
app.post('/api/auth/login', async (req,res)=>{
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({error:'username e password são obrigatórios'});
  try{
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    const users = JSON.parse(raw);
    const user = users.find(u=>u.username === username);
    if(!user) return res.status(401).json({error:'Credenciais inválidas'});
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(401).json({error:'Credenciais inválidas'});
    const token = jwt.sign({username: user.username}, JWT_SECRET, {expiresIn:'12h'});
    res.json({token});
  }catch(err){
    console.error('Erro no login:', err);
    res.status(500).json({error:'Erro interno'});
  }
});

// Products API
app.get('/api/products', async (req,res)=>{
  try{
    const products = await readProducts();
    res.json(products);
  }catch(err){
    console.error('Erro lendo produtos:', err);
    res.status(500).json({error:'Erro ao ler produtos'});
  }
});

app.post('/api/products', authenticateToken, async (req,res)=>{
  const data = req.body;
  const products = await readProducts();
  const id = products.length ? Math.max(...products.map(p=>p.id||0))+1 : 1;
  const item = Object.assign({id}, data);
  products.push(item);
  await writeProducts(products);
  res.status(201).json(item);
});

app.put('/api/products/:id', authenticateToken, async (req,res)=>{
  const id = Number(req.params.id);
  const products = await readProducts();
  const idx = products.findIndex(p=>p.id === id);
  if(idx === -1) return res.status(404).json({error:'Produto não encontrado'});
  products[idx] = Object.assign({}, products[idx], req.body, {id});
  await writeProducts(products);
  res.json(products[idx]);
});

app.delete('/api/products/:id', authenticateToken, async (req,res)=>{
  const id = Number(req.params.id);
  let products = await readProducts();
  const newList = products.filter(p=>p.id !== id);
  if(newList.length === products.length) return res.status(404).json({error:'Produto não encontrado'});
  await writeProducts(newList);
  res.status(204).end();
});

// change password endpoint (authenticated)
app.post('/api/auth/change-password', authenticateToken, async (req,res)=>{
  const { oldPassword, newPassword } = req.body;
  if(!oldPassword || !newPassword) return res.status(400).json({error:'oldPassword + newPassword são necessários'});
  try{
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    const users = JSON.parse(raw);
    const user = users.find(u=>u.username === req.user.username);
    if(!user) return res.status(404).json({error:'Usuário não encontrado'});
    const ok = await bcrypt.compare(oldPassword, user.passwordHash);
    if(!ok) return res.status(401).json({error:'Senha atual incorreta'});
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
    res.json({ok:true});
  }catch(err){
    console.error('Erro cambiando senha:', err);
    res.status(500).json({error:'Erro interno'});
  }
});

// start
(async ()=>{
  await ensureFiles();
  app.listen(PORT, ()=> console.log('Server running on http://localhost:'+PORT));
})();
