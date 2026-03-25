// app.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = 3000;
const SECRET = "jwt-secret-key";

// ================= MIDDLEWARE =================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Session middleware for web
app.use(session({
  secret: 'web-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set true if HTTPS
}));

// EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ================= DATABASE =================
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'demo_f1',
  password: '123456',
  port: 5432,
});

// ================= ROOT =================
app.get('/log', (req,res)=>{
  res.json({
    message:"Auth API Running",
    endpoints:{
      webLogin:"GET /login",
      apiLogin:"POST /api/login",
      adminDashboard:"GET /admin-dashboard (web) /api/admin/dashboard (api)",
      userDashboard:"GET /user-dashboard (web) /api/user/dashboard (api)",
      adminListUsers:"GET /api/admin/users"
    }
  });
});

// ================= WEB LOGIN =================
app.get('/', (req,res)=>{
  res.render('login', { error: null });
});

app.post('/login', async (req,res)=>{
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1",[email]);
    if(result.rows.length === 0) return res.render('login', { error: "User not found" });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if(!validPassword) return res.render('login', { error: "Invalid password" });

    // Save user in session for web
    req.session.user = { id: user.id, email: user.email, role: user.role };

    // Redirect based on role
    if(user.role === "admin") res.redirect("/admin-dashboard");
    else res.redirect("/user-dashboard");

  } catch(err){
    res.render('login', { error: "Server error" });
  }
});

// Web Logout
app.get('/logout', (req,res)=>{
  req.session.destroy(err=>{
    if(err) return res.send("Error logging out");
    res.redirect('/login');
  });
});

// ================= WEB DASHBOARDS =================

// Admin dashboard (web)
app.get('/admin-dashboard', (req,res)=>{
  const user = req.session.user;
  if(!user || user.role !== "admin") return res.redirect('/login');
  res.render('admin-dashboard', { user });
});

// User dashboard (web)
app.get('/user-dashboard', (req,res)=>{
  const user = req.session.user;
  if(!user) return res.redirect('/login');
  res.render('user-dashboard', { user });
});

// User project page (web)
app.get('/user/projects', async (req,res)=>{
  const user = req.session.user;
  if(!user) return res.redirect('/login');

  try{
    const result = await pool.query(`
      SELECT p.id, p.name, p.description,
             COALESCE(up.status, 'pending') AS status
      FROM projects p
      LEFT JOIN user_projects up
      ON p.id = up.project_id AND up.user_id = $1
      ORDER BY p.created_at DESC
    `,[user.id]);

    res.render('user-projects', { user, projects: result.rows });
  }catch(err){
    res.send("Error loading projects");
  }
});

// Admin project page (web)
app.get('/admin/projects', async (req, res) => {
  const user = req.session.user;
  if (!user || user.role !== "admin") return res.redirect('/login');

  try {
    // Get all projects with user decisions
    const projectsResult = await pool.query(`
      SELECT p.id, p.name, p.description, p.created_at,
             COALESCE(json_agg(
               json_build_object(
                 'user_id', u.id,
                 'email', u.email,
                 'status', up.status
               )
             ) FILTER (WHERE u.id IS NOT NULL), '[]') AS user_decisions
      FROM projects p
      LEFT JOIN user_projects up ON p.id = up.project_id
      LEFT JOIN users u ON u.id = up.user_id
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `);

    // Get all users (to populate the assign dropdown)
    const usersResult = await pool.query("SELECT id, email FROM users");

    res.render('admin-projects', { 
      user, 
      projects: projectsResult.rows,
      allUsers: usersResult.rows
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading admin projects");
  }
});

// Web: Create project (admin)
app.post('/admin/projects', async (req,res)=>{
  const user = req.session.user;
  if(!user || user.role !== "admin") return res.redirect('/login');

  const { name, description } = req.body;

  try{
    await pool.query(
      "INSERT INTO projects (name, description) VALUES ($1, $2)",
      [name, description]
    );
    res.redirect('/admin/projects');
  }catch(err){
    console.error(err);
    res.send("Error creating project");
  }
});

// Web: Assign project to user (admin)
app.post('/admin/projects/:id/assign', async (req,res)=>{
  const user = req.session.user;
  if(!user || user.role !== "admin") return res.redirect('/login');

  const project_id = req.params.id;
  const { user_id } = req.body;

  try{
    await pool.query(`
      INSERT INTO user_projects (user_id, project_id, status)
      VALUES ($1, $2, 'pending')
      ON CONFLICT (user_id, project_id)
      DO NOTHING
    `,[user_id, project_id]);

    res.redirect('/admin/projects');
  }catch(err){
    console.error(err);
    res.send("Error assigning project");
  }
});

// ================= API LOGIN (ANDROID/POSTMAN) =================
app.post('/api/login', async (req,res)=>{
  const { email, password } = req.body;
  try{
    const result = await pool.query("SELECT * FROM users WHERE email=$1",[email]);
    if(result.rows.length === 0) return res.status(401).json({ success:false, message:"User not found" });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password,user.password);
    if(!validPassword) return res.status(401).json({ success:false, message:"Invalid password" });

    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, SECRET, { expiresIn:"24h" });

    res.json({
      success:true,
      message:"Login successful",
      token,
      user:{ id:user.id, email:user.email, role:user.role }
    });

  }catch(err){
    console.error(err);
    res.status(500).json({ success:false, message:"Server error" });
  }
});

// ================= AUTH MIDDLEWARE =================
function authenticateToken(req,res,next){
  const authHeader = req.headers['authorization'];
  if(!authHeader) return res.status(401).json({message:"Token required"});

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET, (err,user)=>{
    if(err) return res.status(403).json({message:"Invalid token"});
    req.user = user;
    next();
  });
}

function adminOnly(req,res,next){
  if(req.user.role !== "admin") return res.status(403).json({ message:"Admin access only" });
  next();
}

// ================= API DASHBOARDS =================
app.get('/api/admin/dashboard', authenticateToken, adminOnly, (req,res)=>{
  res.json({ message:"Welcome Admin", admin:req.user });
});

app.get('/api/user/dashboard', authenticateToken, (req,res)=>{
  res.json({ message:"Welcome User", user:req.user });
});

// ================= ADMIN USER MANAGEMENT =================
app.get('/api/admin/users', authenticateToken, adminOnly, async (req,res)=>{
  try{
    const users = await pool.query("SELECT id,email,role FROM users");
    res.json(users.rows);
  }catch(err){
    res.status(500).json({ message:"Server error" });
  }
});

app.delete('/api/admin/user/:id', authenticateToken, adminOnly, async (req,res)=>{
  const { id } = req.params;
  try{
    await pool.query("DELETE FROM users WHERE id=$1", [id]);
    res.json({ message:"User deleted" });
  }catch(err){
    res.status(500).json({ message:"Server error" });
  }
});

// ================= PROJECTS API =================

// Get all projects for a user
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.name, p.description,
             COALESCE(up.status, 'pending') AS status
      FROM projects p
      LEFT JOIN user_projects up
      ON p.id = up.project_id AND up.user_id = $1
      ORDER BY p.created_at DESC
    `, [req.user.id]);

    res.json({ success: true, projects: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// User decides on a project
app.post('/api/projects/:id/decision', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if(!['accepted','rejected','hold'].includes(status)) 
    return res.status(400).json({ success: false, message: "Invalid status" });

  try {
    await pool.query(`
      INSERT INTO user_projects (user_id, project_id, status)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, project_id)
      DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
    `, [req.user.id, id, status]);

    res.json({ success: true, message: `Project ${status}` });
  } catch(err){
    console.error(err);
    res.status(500).json({ success:false, message:"Server error" });
  }
});

// WEB: user decision using session
app.post('/projects/:id/decision', async (req,res)=>{
  const user = req.session.user;
  if(!user) return res.redirect('/login');

  const { id } = req.params;
  const { status } = req.body;

  if(!['accepted','rejected','hold'].includes(status)){
    return res.send("Invalid status");
  }

  try{
    await pool.query(`
      INSERT INTO user_projects (user_id, project_id, status)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, project_id)
      DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
    `,[user.id, id, status]);

    res.redirect('/user/projects');

  }catch(err){
    console.error(err);
    res.send("Server error");
  }
});

// Admin: create a project
app.post('/api/admin/projects', authenticateToken, adminOnly, async (req, res) => {
  const { name, description } = req.body;

  try {
    const result = await pool.query(
      "INSERT INTO projects (name, description) VALUES ($1, $2) RETURNING *",
      [name, description]
    );
    res.json({ success: true, project: result.rows[0] });
  } catch(err){
    console.error(err);
    res.status(500).json({ success:false, message:"Server error" });
  }
});

// Admin: list all projects with user decisions
app.get('/api/admin/projects', authenticateToken, adminOnly, async (req,res)=>{
  try{
    const result = await pool.query(`
      SELECT p.id, p.name, p.description, p.created_at,
             json_agg(
               json_build_object(
                 'user_id', u.id,
                 'email', u.email,
                 'status', up.status
               )
             ) AS user_decisions
      FROM projects p
      LEFT JOIN user_projects up ON p.id = up.project_id
      LEFT JOIN users u ON u.id = up.user_id
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `);
    res.json({ success:true, projects: result.rows });
  }catch(err){
    console.error(err);
    res.status(500).json({ success:false, message:"Server error" });
  }
});
// Assign project to user
app.post('/api/admin/projects/:id/assign', authenticateToken, adminOnly, async (req,res)=>{
  const { id } = req.params;  // project_id
  const { user_id } = req.body;

  try{
    await pool.query(`
      INSERT INTO user_projects (user_id, project_id, status)
      VALUES ($1, $2, 'pending')
      ON CONFLICT (user_id, project_id)
      DO NOTHING
    `, [user_id, id]);

    res.json({ success:true, message:'User assigned to project' });
  }catch(err){
    console.error(err);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// ================= SERVER =================
app.listen(PORT, ()=>{
  console.log(`Server running on http://localhost:${PORT}`);
});