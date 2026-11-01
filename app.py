import os, sqlite3, secrets, json, hmac, hashlib, time
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('VYREX_DATA_DIR',str(ROOT/'data'))); DATA.mkdir(parents=True,exist_ok=True)
DB=DATA/'data.sqlite3'; UP=DATA/'uploads'; UP.mkdir(exist_ok=True)
app=Flask(__name__, static_folder='static', static_url_path='')
app.secret_key=os.environ.get('VYREX_SECRET_KEY')
if not app.secret_key or len(app.secret_key)<32: raise RuntimeError('VYREX_SECRET_KEY must be set (at least 32 characters)')
app.wsgi_app=ProxyFix(app.wsgi_app,x_for=1,x_proto=1,x_host=1)
app.config.update(MAX_CONTENT_LENGTH=12*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=True, PERMANENT_SESSION_LIFETIME=3600)
CATS=('Peptides','Oils','Tablets')

def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c

def init():
 c=db();c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT);
 CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,spec TEXT NOT NULL,cat TEXT NOT NULL,unit_price REAL,bulk_price REAL,image TEXT,coa TEXT,visible INTEGER NOT NULL DEFAULT 1,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS inquiries(id INTEGER PRIMARY KEY,customer_name TEXT NOT NULL,email TEXT NOT NULL,message TEXT,items_json TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'new',created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL DEFAULT '');''')
 if not c.execute('SELECT 1 FROM users').fetchone():
  username=os.environ.get('VYREX_ADMIN_USER','admin')
  password=os.environ.get('VYREX_ADMIN_PASSWORD')
  if not password or len(password)<12: raise RuntimeError('Set VYREX_ADMIN_PASSWORD (at least 12 characters) before first run')
  c.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',(username,generate_password_hash(password)))
 c.commit();c.close()
init()

@app.after_request
def security_headers(response):
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Cache-Control']='no-store' if request.path.startswith('/api/') or request.path=='/admin' else 'public, max-age=300'
 return response

# Basic origin protection for mutating requests (CSRF tokens protect logged-in writes).
@app.before_request
def check_origin():
 if request.method in ('POST','PUT','PATCH','DELETE'):
  origin=request.headers.get('Origin')
  if origin and origin.rstrip('/')!=request.host_url.rstrip('/'):
   return jsonify(error='请求来源不被允许'),403

LOGIN_FAILURES={}

def admin_required(fn):
 @wraps(fn)
 def f(*a,**k):
  if not session.get('admin'):return jsonify(error='请先登录管理员后台'),401
  return fn(*a,**k)
 return f

def csrf_required(fn):
 @wraps(fn)
 def f(*a,**k):
  if session.get('admin') and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),session.get('csrf','')):return jsonify(error='安全校验失败，请刷新页面'),403
  return fn(*a,**k)
 return f

@app.get('/')
def home():return app.send_static_file('index.html')
@app.get('/admin')
def adminpage():return app.send_static_file('admin.html')
@app.post('/api/login')
def login():
 d=request.get_json(silent=True) or {};c=db();u=c.execute('SELECT * FROM users WHERE username=?',(str(d.get('username','')),)).fetchone();c.close()
 ip=request.remote_addr or 'unknown'; now=time.time()
 attempts=[t for t in LOGIN_FAILURES.get(ip,[]) if now-t<900]
 if len(attempts)>=8:return jsonify(error='登录尝试过多，请15分钟后再试'),429
 if not u or not check_password_hash(u['password_hash'],str(d.get('password',''))):
  attempts.append(now);LOGIN_FAILURES[ip]=attempts
  return jsonify(error='账号或密码错误'),401
 LOGIN_FAILURES.pop(ip,None)
 session.clear();session['admin']=True;session['csrf']=secrets.token_urlsafe(24);return jsonify(ok=True,csrf=session['csrf'])
@app.get('/api/me')
def me():return jsonify(admin=bool(session.get('admin')),csrf=session.get('csrf'))
@app.post('/api/logout')
@admin_required
@csrf_required
def logout():session.clear();return jsonify(ok=True)
@app.post('/api/change-password')
@admin_required
@csrf_required
def change_password():
 d=request.get_json(silent=True) or {}
 current=str(d.get('current_password',''))
 new=str(d.get('new_password',''))
 confirm=str(d.get('confirm_password',''))
 if not current or not new or not confirm:
  return jsonify(error='请填写当前密码、新密码和确认密码'),400
 if len(new)<12:
  return jsonify(error='新密码至少需要12个字符'),400
 if new!=confirm:
  return jsonify(error='两次输入的新密码不一致'),400
 c=db()
 # This application currently provisions one administrator account.
 u=c.execute('SELECT id,password_hash FROM users ORDER BY id LIMIT 1').fetchone()
 if not u or not check_password_hash(u['password_hash'],current):
  c.close()
  return jsonify(error='当前密码不正确'),400
 c.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),u['id']))
 c.commit()
 c.close()
 session.clear()
 return jsonify(ok=True,message='密码修改成功，请使用新密码重新登录',relogin=True)

@app.get('/api/contact')
def get_contact():
 c=db();rows=c.execute("SELECT k,v FROM settings WHERE k IN ('whatsapp','email','phone','telegram','address','hours')").fetchall();c.close()
 return jsonify({**{k:'' for k in ('whatsapp','email','phone','telegram','address','hours')},**{r['k']:r['v'] for r in rows}})
@app.put('/api/contact')
@admin_required
@csrf_required
def save_contact():
 d=request.get_json(silent=True) or {}
 keys=('whatsapp','email','phone','telegram','address','hours')
 if not isinstance(d,dict):return jsonify(error='数据格式错误'),400
 vals={k:str(d.get(k,'')).strip() for k in keys}
 if any(len(v)>300 for v in vals.values()):return jsonify(error='每项最多300字符'),400
 if vals['email'] and ('@' not in vals['email'] or ' ' in vals['email']):return jsonify(error='邮箱格式不正确'),400
 if vals['whatsapp'] and not vals['whatsapp'].lstrip('+').isdigit():return jsonify(error='WhatsApp 请输入国家代码和电话号码，例如 +12345678900'),400
 c=db()
 with c:
  c.executemany('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',vals.items())
 c.close();return jsonify(ok=True)
@app.get('/api/products')
def products():
 c=db();rows=c.execute('SELECT * FROM products '+('' if session.get('admin') else 'WHERE visible=1 ')+'ORDER BY id DESC').fetchall();c.close()
 out=[]
 for r in rows:
  p=dict(r)
  if not session.get('admin'):p.pop('updated_at',None)
  out.append(p)
 return jsonify(out)

def valid_product(d):
 code=str(d.get('code','')).strip().upper();name=str(d.get('name','')).strip();spec=str(d.get('spec','')).strip();cat=d.get('cat')
 if not code or len(code)>32 or not all(ch.isalnum() or ch in '-_' for ch in code):raise ValueError('代码只能包含字母、数字、-、_，最多32字符')
 if not name or len(name)>150 or not spec or len(spec)>160 or cat not in CATS:raise ValueError('请填写有效名称、规格和分类')
 def price(k):
  v=d.get(k)
  if v is None or v=='':return None
  n=float(v)
  if not 0<=n<=10000000:raise ValueError('价格范围无效')
  return round(n,2)
 return (code,name,spec,cat,price('unit_price'),price('bulk_price'),int(bool(d.get('visible',True))))
@app.post('/api/products')
@admin_required
@csrf_required
def add_product():
 try:
  v=valid_product(request.get_json() or {});c=db();cur=c.execute('INSERT INTO products(code,name,spec,cat,unit_price,bulk_price,visible) VALUES(?,?,?,?,?,?,?)',v);c.commit();pid=cur.lastrowid;c.close();return jsonify(id=pid)
 except (ValueError,sqlite3.IntegrityError) as e:return jsonify(error=str(e)),400
@app.put('/api/products/<int:pid>')
@admin_required
@csrf_required
def update_product(pid):
 try:
  v=valid_product(request.get_json() or {});c=db();cur=c.execute('UPDATE products SET code=?,name=?,spec=?,cat=?,unit_price=?,bulk_price=?,visible=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(*v,pid));c.commit();changed=cur.rowcount;c.close();return jsonify(ok=bool(changed))
 except (ValueError,sqlite3.IntegrityError) as e:return jsonify(error=str(e)),400
@app.delete('/api/products/<int:pid>')
@admin_required
@csrf_required
def del_product(pid):
 c=db();c.execute('DELETE FROM products WHERE id=?',(pid,));c.commit();c.close();return jsonify(ok=True)
@app.post('/api/products/<int:pid>/upload/<kind>')
@admin_required
@csrf_required
def upload(pid,kind):
 if kind not in ('image','coa'):abort(404)
 f=request.files.get('file')
 if not f:return jsonify(error='请选择文件'),400
 suffix=Path(secure_filename(f.filename)).suffix.lower()
 allowed={'.png','.jpg','.jpeg','.webp'} if kind=='image' else {'.pdf'}
 if suffix not in allowed:return jsonify(error='仅允许图片 PNG/JPG/WEBP 或 COA PDF'),400
 signature=f.stream.read(16);f.stream.seek(0)
 if kind=='coa' and not signature.startswith(b'%PDF-'):return jsonify(error='文件不是有效的 PDF'),400
 if kind=='image' and not (signature.startswith(b'\x89PNG\r\n\x1a\n') or signature.startswith(b'\xff\xd8\xff') or signature.startswith(b'RIFF') and signature[8:12]==b'WEBP'):return jsonify(error='图片格式不正确'),400
 c=db();row=c.execute('SELECT id FROM products WHERE id=?',(pid,)).fetchone()
 if not row:c.close();return jsonify(error='产品不存在'),404
 fn=f'{secrets.token_hex(16)}{suffix}';f.save(UP/fn);url=f'/uploads/{fn}'
 c.execute(f'UPDATE products SET {kind}=? WHERE id=?',(url,pid));c.commit();c.close();return jsonify(url=url)
@app.get('/uploads/<path:filename>')
def get_upload(filename):
 if '/' in filename or '..' in filename:abort(404)
 # public files linked to published products only
 c=db();row=c.execute('SELECT id FROM products WHERE visible=1 AND (image=? OR coa=?)',(f'/uploads/{filename}',f'/uploads/{filename}')).fetchone();c.close()
 if not row and not session.get('admin'):abort(404)
 return send_from_directory(UP,filename)
@app.post('/api/inquiries')
def inquiry():
 d=request.get_json(silent=True) or {};name=str(d.get('name','')).strip();email=str(d.get('email','')).strip();message=str(d.get('message','')).strip();items=d.get('items',[])
 if not 1<=len(name)<=100 or not 3<=len(email)<=180 or '@' not in email or len(message)>2000 or not isinstance(items,list) or len(items)>100:return jsonify(error='请填写姓名、邮箱和有效的询价产品'),400
 clean=[];c=db()
 for i in items:
  if not isinstance(i,dict):continue
  try: pid=int(i.get('id'));qty=int(i.get('qty'))
  except (TypeError,ValueError):continue
  p=c.execute('SELECT id,code,name,spec FROM products WHERE id=? AND visible=1',(pid,)).fetchone()
  if p and 1<=qty<=999:clean.append({**dict(p),'qty':qty})
 if not clean:c.close();return jsonify(error='请添加至少一款有效产品'),400
 c.execute('INSERT INTO inquiries(customer_name,email,message,items_json) VALUES(?,?,?,?)',(name,email,message,json.dumps(clean,ensure_ascii=False)));c.commit();c.close();return jsonify(ok=True)
@app.get('/api/inquiries')
@admin_required
def inquiries():
 c=db();data=[dict(r) for r in c.execute('SELECT * FROM inquiries ORDER BY id DESC')];c.close()
 for r in data:r['items']=json.loads(r.pop('items_json'))
 return jsonify(data)
@app.patch('/api/inquiries/<int:iid>')
@admin_required
@csrf_required
def inquiry_status(iid):
 status=(request.get_json() or {}).get('status')
 if status not in ('new','processing','closed'):return jsonify(error='状态无效'),400
 c=db();c.execute('UPDATE inquiries SET status=? WHERE id=?',(status,iid));c.commit();c.close();return jsonify(ok=True)
if __name__=='__main__':
 app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
 response.headers['X-Frame-Options']='DENY'
 response.headers['Cache-Control']='no-store' if request.path.startswith('/api/') or request.path=='/admin' else 'public, max-age=300'
 return response

# Basic origin protection for mutating requests (CSRF tokens protect logged-in writes).
@app.before_request
def check_origin():
 if request.method in ('POST','PUT','PATCH','DELETE'):
  origin=request.headers.get('Origin')
  if origin and origin.rstrip('/')!=request.host_url.rstrip('/'):
   return jsonify(error='请求来源不被允许'),403

LOGIN_FAILURES={}

def admin_required(fn):
 @wraps(fn)
 def f(*a,**k):
  if not session.get('admin'):return jsonify(error='请先登录管理员后台'),401
  return fn(*a,**k)
 return f

def csrf_required(fn):
 @wraps(fn)
 def f(*a,**k):
  if session.get('admin') and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),session.get('csrf','')):return jsonify(error='安全校验失败，请刷新页面'),403
  return fn(*a,**k)
 return f

@app.get('/')
def home():return app.send_static_file('index.html')
@app.get('/admin')
def adminpage():return app.send_static_file('admin.html')
@app.post('/api/login')
def login():
 d=request.get_json(silent=True) or {};c=db();u=c.execute('SELECT * FROM users WHERE username=?',(str(d.get('username','')),)).fetchone();c.close()
 ip=request.remote_addr or 'unknown'; now=time.time()
 attempts=[t for t in LOGIN_FAILURES.get(ip,[]) if now-t<900]
 if len(attempts)>=8:return jsonify(error='登录尝试过多，请15分钟后再试'),429
 if not u or not check_password_hash(u['password_hash'],str(d.get('password',''))):
  attempts.append(now);LOGIN_FAILURES[ip]=attempts
  return jsonify(error='账号或密码错误'),401
 LOGIN_FAILURES.pop(ip,None)
 session.clear();session['admin']=True;session['csrf']=secrets.token_urlsafe(24);return jsonify(ok=True,csrf=session['csrf'])
@app.get('/api/me')
def me():return jsonify(admin=bool(session.get('admin')),csrf=session.get('csrf'))
@app.post('/api/logout')
@admin_required
@csrf_required
def logout():session.clear();return jsonify(ok=True)
@app.post('/api/change-password')
@admin_required
@csrf_required
def change_password():
 d=request.get_json(silent=True) or {}
 current=str(d.get('current_password',''))
 new=str(d.get('new_password',''))
 confirm=str(d.get('confirm_password',''))
 if not current or not new or not confirm:
  return jsonify(error='请填写当前密码、新密码和确认密码'),400
 if len(new)<12:
  return jsonify(error='新密码至少需要12个字符'),400
 if new!=confirm:
  return jsonify(error='两次输入的新密码不一致'),400
 c=db()
 # This application currently provisions one administrator account.
 u=c.execute('SELECT id,password_hash FROM users ORDER BY id LIMIT 1').fetchone()
 if not u or not check_password_hash(u['password_hash'],current):
  c.close()
  return jsonify(error='当前密码不正确'),400
 c.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),u['id']))
 c.commit()
 c.close()
 session.clear()
 return jsonify(ok=True,message='密码修改成功，请使用新密码重新登录',relogin=True)

@app.get('/api/contact')
def get_contact():
 c=db();rows=c.execute("SELECT k,v FROM settings WHERE k IN ('whatsapp','email','phone','telegram','address','hours')").fetchall();c.close()
 return jsonify({**{k:'' for k in ('whatsapp','email','phone','telegram','address','hours')},**{r['k']:r['v'] for r in rows}})
@app.put('/api/contact')
@admin_required
@csrf_required
def save_contact():
 d=request.get_json(silent=True) or {}
 keys=('whatsapp','email','phone','telegram','address','hours')
 if not isinstance(d,dict):return jsonify(error='数据格式错误'),400
 vals={k:str(d.get(k,'')).strip() for k in keys}
 if any(len(v)>300 for v in vals.values()):return jsonify(error='每项最多300字符'),400
 if vals['email'] and ('@' not in vals['email'] or ' ' in vals['email']):return jsonify(error='邮箱格式不正确'),400
 if vals['whatsapp'] and not vals['whatsapp'].lstrip('+').isdigit():return jsonify(error='WhatsApp 请输入国家代码和电话号码，例如 +12345678900'),400
 c=db()
 with c:
  c.executemany('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',vals.items())
 c.close();return jsonify(ok=True)
@app.get('/api/products')
def products():
 c=db();rows=c.execute('SELECT * FROM products '+('' if session.get('admin') else 'WHERE visible=1 ')+'ORDER BY id DESC').fetchall();c.close()
 out=[]
 for r in rows:
  p=dict(r)
  if not session.get('admin'):p.pop('updated_at',None)
  out.append(p)
 return jsonify(out)

def valid_product(d):
 code=str(d.get('code','')).strip().upper();name=str(d.get('name','')).strip();spec=str(d.get('spec','')).strip();cat=d.get('cat')
 if not code or len(code)>32 or not all(ch.isalnum() or ch in '-_' for ch in code):raise ValueError('代码只能包含字母、数字、-、_，最多32字符')
 if not name or len(name)>150 or not spec or len(spec)>160 or cat not in CATS:raise ValueError('请填写有效名称、规格和分类')
 def price(k):
  v=d.get(k)
  if v is None or v=='':return None
  n=float(v)
  if not 0<=n<=10000000:raise ValueError('价格范围无效')
  return round(n,2)
 return (code,name,spec,cat,price('unit_price'),price('bulk_price'),int(bool(d.get('visible',True))))
@app.post('/api/products')
@admin_required
@csrf_required
def add_product():
 try:
  v=valid_product(request.get_json() or {});c=db();cur=c.execute('INSERT INTO products(code,name,spec,cat,unit_price,bulk_price,visible) VALUES(?,?,?,?,?,?,?)',v);c.commit();pid=cur.lastrowid;c.close();return jsonify(id=pid)
 except (ValueError,sqlite3.IntegrityError) as e:return jsonify(error=str(e)),400
@app.put('/api/products/<int:pid>')
@admin_required
@csrf_required
def update_product(pid):
 try:
  v=valid_product(request.get_json() or {});c=db();cur=c.execute('UPDATE products SET code=?,name=?,spec=?,cat=?,unit_price=?,bulk_price=?,visible=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(*v,pid));c.commit();changed=cur.rowcount;c.close();return jsonify(ok=bool(changed))
 except (ValueError,sqlite3.IntegrityError) as e:return jsonify(error=str(e)),400
@app.delete('/api/products/<int:pid>')
@admin_required
@csrf_required
def del_product(pid):
 c=db();c.execute('DELETE FROM products WHERE id=?',(pid,));c.commit();c.close();return jsonify(ok=True)
@app.post('/api/products/<int:pid>/upload/<kind>')
@admin_required
@csrf_required
def upload(pid,kind):
 if kind not in ('image','coa'):abort(404)
 f=request.files.get('file')
 if not f:return jsonify(error='请选择文件'),400
 suffix=Path(secure_filename(f.filename)).suffix.lower()
 allowed={'.png','.jpg','.jpeg','.webp'} if kind=='image' else {'.pdf'}
 if suffix not in allowed:return jsonify(error='仅允许图片 PNG/JPG/WEBP 或 COA PDF'),400
 signature=f.stream.read(16);f.stream.seek(0)
 if kind=='coa' and not signature.startswith(b'%PDF-'):return jsonify(error='文件不是有效的 PDF'),400
 if kind=='image' and not (signature.startswith(b'\x89PNG\r\n\x1a\n') or signature.startswith(b'\xff\xd8\xff') or signature.startswith(b'RIFF') and signature[8:12]==b'WEBP'):return jsonify(error='图片格式不正确'),400
 c=db();row=c.execute('SELECT id FROM products WHERE id=?',(pid,)).fetchone()
 if not row:c.close();return jsonify(error='产品不存在'),404
 fn=f'{secrets.token_hex(16)}{suffix}';f.save(UP/fn);url=f'/uploads/{fn}'
 c.execute(f'UPDATE products SET {kind}=? WHERE id=?',(url,pid));c.commit();c.close();return jsonify(url=url)
@app.get('/uploads/<path:filename>')
def get_upload(filename):
 if '/' in filename or '..' in filename:abort(404)
 # public files linked to published products only
 c=db();row=c.execute('SELECT id FROM products WHERE visible=1 AND (image=? OR coa=?)',(f'/uploads/{filename}',f'/uploads/{filename}')).fetchone();c.close()
 if not row and not session.get('admin'):abort(404)
 return send_from_directory(UP,filename)
@app.post('/api/inquiries')
def inquiry():
 d=request.get_json(silent=True) or {};name=str(d.get('name','')).strip();email=str(d.get('email','')).strip();message=str(d.get('message','')).strip();items=d.get('items',[])
 if not 1<=len(name)<=100 or not 3<=len(email)<=180 or '@' not in email or len(message)>2000 or not isinstance(items,list) or len(items)>100:return jsonify(error='请填写姓名、邮箱和有效的询价产品'),400
 clean=[];c=db()
 for i in items:
  if not isinstance(i,dict):continue
  try: pid=int(i.get('id'));qty=int(i.get('qty'))
  except (TypeError,ValueError):continue
  p=c.execute('SELECT id,code,name,spec FROM products WHERE id=? AND visible=1',(pid,)).fetchone()
  if p and 1<=qty<=999:clean.append({**dict(p),'qty':qty})
 if not clean:c.close();return jsonify(error='请添加至少一款有效产品'),400
 c.execute('INSERT INTO inquiries(customer_name,email,message,items_json) VALUES(?,?,?,?)',(name,email,message,json.dumps(clean,ensure_ascii=False)));c.commit();c.close();return jsonify(ok=True)
@app.get('/api/inquiries')
@admin_required
def inquiries():
 c=db();data=[dict(r) for r in c.execute('SELECT * FROM inquiries ORDER BY id DESC')];c.close()
 for r in data:r['items']=json.loads(r.pop('items_json'))
 return jsonify(data)
@app.patch('/api/inquiries/<int:iid>')
@admin_required
@csrf_required
def inquiry_status(iid):
 status=(request.get_json() or {}).get('status')
 if status not in ('new','processing','closed'):return jsonify(error='状态无效'),400
 c=db();c.execute('UPDATE inquiries SET status=? WHERE id=?',(status,iid));c.commit();c.close();return jsonify(ok=True)
if __name__=='__main__':
 app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
