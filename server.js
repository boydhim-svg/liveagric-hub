// LiveAgric Smart hub server. Needs only Node.js 18+ (no npm install).
// Run: node server.js   Admin page: http://localhost:3000/admin
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,DIR=process.env.DATA_DIR||path.join(__dirname,'data'),FILE=path.join(DIR,'db.json');
fs.mkdirSync(DIR,{recursive:true});
let db={pay:[],req:[],lst:[],n:0,admin:null,set:{
  merchants:{'Airtel Money':{number:'',label:'Airtel Money'},'MTN Mobile Money':{number:'',label:'MTN Mobile Money'},'Zamtel Kwacha':{number:'',label:'Zamtel Kwacha'}},
  fees:{assessment:10,listing:30,training:25},
auto:false,
listingDays:3}};
try{db={...db,...JSON.parse(fs.readFileSync(FILE,'utf8'))}}catch(e){}
const save=()=>{fs.writeFileSync(FILE+'.tmp',JSON.stringify(db));fs.renameSync(FILE+'.tmp',FILE)};
const hash=(p,s=crypto.randomBytes(16).toString('hex'))=>s+':'+crypto.scryptSync(p,s,32).toString('hex');
const check=(p,h)=>{const [s,x]=h.split(':'),y=hash(p,s).split(':')[1];return crypto.timingSafeEqual(Buffer.from(x,'hex'),Buffer.from(y,'hex'))};
if(!db.admin){ // first run: create the admin password in the background
  const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(7).toString('base64url');
  db.admin=hash(pw);save();
  console.log('\n=== FIRST ADMIN PASSWORD: '+pw+' (change it in Settings & Tools) ===\n');
  if(!process.env.ADMIN_PASSWORD)fs.writeFileSync(path.join(DIR,'FIRST-LOGIN.txt'),'Admin password: '+pw+'\nDelete this file after changing the password.\n');
}
const sess=new Map(),hits=new Map();
const limit=(k,max,ms)=>{const n=Date.now(),h=(hits.get(k)||[]).filter(t=>n-t<ms);h.push(n);hits.set(k,h);return h.length>max};
const rid=()=>'LA-'+crypto.randomBytes(4).toString('hex').toUpperCase();
const txt=(v,n)=>String(v==null?'':v).replace(/[<>]/g,'').trim().slice(0,n);
const prod=(k,s)=>k==='assessment'?'Triage report':k==='listing'?'Marketplace listing':k==='training'?'Manual guide':/Training/i.test(s||'')?'Virtual training':'Consultation call';
const expire=()=>{const t=Date.now()-864e5;db.pay.forEach(p=>{if((p.status==='INITIATED'||p.status==='PENDING')&&p.created<t)p.status='EXPIRED'})};
const body=req=>new Promise((ok,no)=>{let d='';req.on('data',c=>{d+=c;if(d.length>1e5){no(new Error('Too large'));req.destroy()}});req.on('end',()=>{try{ok(d?JSON.parse(d):{})}catch(e){no(new Error('Bad request'))}})});

http.createServer(async(req,res)=>{
  const p=new URL(req.url,'http://x').pathname.replace(/\/+$/,'')||'/',m=req.method;
  const ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress;
  const send=(c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...h});res.end(JSON.stringify(o))};
  const fail=(c,e)=>send(c,{error:e});
  try{
    if(p==='/admin'){
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Frame-Options':'DENY','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
        'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"});
      return res.end(fs.readFileSync(path.join(__dirname,'admin.html')));
    }
    if(p==='/')return send(200,{ok:true,service:'LiveAgric server'});
    // ---------- ADMIN API (same-origin only, cookie + header protected) ----------
    if(p.startsWith('/api/admin')){
      const a=p.slice(10)||'/';
      if(m!=='GET'&&req.headers['x-requested-with']!=='la')return fail(403,'Blocked');
      if(a==='/login'&&m==='POST'){
        if(limit('login'+ip,8,9e5))return fail(429,'Too many attempts. Wait 15 minutes.');
        const b=await body(req);
        if(!b.password||!check(String(b.password),db.admin))return fail(401,'Wrong password');
        const t=crypto.randomBytes(24).toString('hex');sess.set(t,Date.now()+288e5);
        return send(200,{ok:true},{'Set-Cookie':`la_admin=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${req.headers['x-forwarded-proto']==='https'||req.socket.encrypted?'; Secure':''}`});
      }
      const tok=((req.headers.cookie||'').split(/;\s*/).find(c=>c.startsWith('la_admin='))||'').slice(9),exp=sess.get(tok);
      if(!exp||exp<Date.now())return fail(401,'Please sign in');
      if(a==='/logout'){sess.delete(tok);return send(200,{ok:true},{'Set-Cookie':'la_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})}
      if(a==='/data'){expire();return send(200,{pay:[...db.pay].reverse(),req:[...db.req].reverse(),lst:[...db.lst].reverse(),set:db.set})}
      let mt;
      if(mt=a.match(/^\/payments\/([\w-]+)$/)){
        const x=db.pay.find(q=>q.ref===mt[1]),b=await body(req);
        if(!x)return fail(404,'Not found');
        if(x.status!=='PENDING')return fail(400,'Only pending payments can be changed');
        x.status=b.action==='confirm'?'CONFIRMED':'REJECTED';x.decided=Date.now();save();return send(200,{ok:true});
      }
      if(mt=a.match(/^\/requests\/([\w-]+)$/)){
        const x=db.req.find(q=>q.id===mt[1]),b=await body(req);
        if(!x)return fail(404,'Not found');
        if(['NEW','CONTACTED','DONE'].includes(b.status))x.status=b.status;
        if(b.note!=null)x.note=txt(b.note,500);
        save();return send(200,{ok:true});
      }
      if(mt=a.match(/^\/listings\/(\d+)$/)&&m==='DELETE'){const x=db.lst.find(q=>q.id==mt[1]);if(x){x.removed=true;save()}return send(200,{ok:true})}
      if(a==='/settings'&&m==='POST'){
        const b=await body(req),s=db.set;
        for(const k of Object.keys(s.merchants))if(b.merchants&&b.merchants[k]!=null)s.merchants[k].number=String(b.merchants[k]).replace(/[^\d+ ]/g,'').slice(0,16);
        for(const k of Object.keys(s.fees)){const v=Number(b.fees&&b.fees[k]);if(v>=0&&v<=10000)s.fees[k]=v}
        s.auto=!!b.auto;

if([3,7,14,30].includes(Number(b.listingDays))){
s.listingDays=Number(b.listingDays);
}save();return send(200,{ok:true});
      }
      if(a==='/password'&&m==='POST'){
        const b=await body(req);
        if(!check(String(b.current||''),db.admin))return fail(400,'Current password is wrong');
        if(String(b.next||'').length<8)return fail(400,'New password must have at least 8 characters');
        db.admin=hash(String(b.next));save();sess.clear();
        try{fs.unlinkSync(path.join(DIR,'FIRST-LOGIN.txt'))}catch(e){}
        return send(200,{ok:true},{'Set-Cookie':'la_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});
      }
      if(a==='/reset'&&m==='POST'){const b=await body(req);if(b.confirm!=='RESET')return fail(400,'Type RESET to confirm');db.pay=[];db.req=[];db.lst=[];save();return send(200,{ok:true})}
      return fail(404,'Not found');
    }
    // ---------- PUBLIC API used by the farmer app ----------
    res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
    if(m==='OPTIONS'){res.writeHead(204);return res.end()}
    if(p==='/config'&&m==='GET')return send(200,{merchants:db.set.merchants});
    if(p==='/listings'&&m==='GET'){

db.lst.forEach(l=>{
if(
!l.removed &&
l.expires &&
Date.now() > l.expires
){
l.removed=true;
}
});

save();

return send(200,{
listings:db.lst
.filter(l=>!l.removed)
.reverse()
.map(l=>({
id:l.id,
title:l.title,
category:l.category,
listingType:l.listingType,
price:l.price,
seller:l.seller,
phone:l.phone,
location:l.location,
period:(db.set.listingDays||3)+' Days'
}))
});

}    if(p==='/payments/init'&&m==='POST'){
      if(limit('init'+ip,40,36e5))return fail(429,'Too many requests. Try again later.');
      const b=await body(req),k=['assessment','listing','training','virtual'].includes(b.kind)?b.kind:'virtual';
      const amt=k==='virtual'?Math.min(5000,Math.max(1,Math.round(Number(b.amount)||0))):db.set.fees[k];
      const x={ref:rid(),kind:k,service:txt(b.service,120),product:prod(k,b.service),amount:amt,status:'INITIATED',created:Date.now(),customer:'',provider:'',payer:'',txn:''};
      db.pay.push(x);save();return send(200,{ref:x.ref,amount:x.amount});
    }
    let mt;
    if(mt=p.match(/^\/payments\/([\w-]+)(\/submit|\/redeem)?$/)){
      const x=db.pay.find(q=>q.ref===mt[1]);if(!x)return fail(404,'Payment not found');
      expire();
      if(!mt[2]&&m==='GET')return send(200,{status:x.status});
      if(mt[2]==='/submit'&&m==='POST'){
        if(x.status!=='INITIATED')return fail(400,'This payment was already submitted');
        const b=await body(req),txn=txt(b.txnId,40).toUpperCase(),payer=txt(b.payer,15);
        if(!db.set.merchants[b.provider])return fail(400,'Choose a Mobile Money provider');
        if(!/^0\d{9}$/.test(payer))return fail(400,'Enter the number you sent from');
        if(!/^[A-Z0-9.\-]{6,40}$/.test(txn))return fail(400,'Enter the Transaction ID from your SMS');
        if(db.pay.some(q=>q.txn===txn&&q!==x))return fail(400,'This Transaction ID was already used');
        Object.assign(x,{provider:b.provider,payer,txn,status:db.set.auto?'CONFIRMED':'PENDING',submitted:Date.now()});save();return send(200,{status:x.status});
      }
      if(mt[2]==='/redeem'&&m==='POST'){
        if(x.status!=='CONFIRMED')return fail(400,'Payment not confirmed yet');
        x.redeemed=true;save();return send(200,{ok:true});
      }
    }
    if(p==='/listings'&&m==='POST'){
      const b=await body(req),x=db.pay.find(q=>q.ref===b.paymentRef);
      if(!x||x.kind!=='listing'||x.status!=='CONFIRMED'||x.listingUsed)return fail(402,'A confirmed listing payment is required');
      const l={id:++db.n,title:txt(b.title,100),category:['livestock','poultry','crops','inputs'].includes(b.category)?b.category:'crops',listingType:b.listingType==='buyer'?'buyer':'seller',
        price:Math.max(0,Number(b.price)||0),seller:txt(b.seller,60),phone:txt(b.phone,15),location:txt(b.location,80),created:Date.now(),
expires:Date.now()+(db.set.listingDays*864e5),
paymentRef:x.ref};
      if(!l.title||!l.seller)return fail(400,'Title and name are required');
      x.listingUsed=true;x.customer=l.seller;db.lst.push(l); console.log('NEW LISTING:', l);save();return send(200,{ok:true,id:l.id});
    }
    if(p==='/requests'&&m==='POST'){
      const b=await body(req),x=db.pay.find(q=>q.ref===b.paymentRef);
      if(!x||x.status!=='CONFIRMED')return fail(402,'A confirmed payment is required');
      if(db.req.some(q=>q.id===txt(b.id,40)))return send(200,{ok:true});
      const r={id:txt(b.id,40),sessionType:b.sessionType==='training'?'training':'consultation',expert:txt(b.expert,60),topic:txt(b.topic,160),dateTime:txt(b.dateTime,40),participants:Math.min(100,Math.max(1,Number(b.participants)||1)),
        farmerName:txt(b.farmerName,60),farmerPhone:txt(b.farmerPhone,15),callDuration:Number(b.callDuration)||0,province:txt(b.province,40),district:txt(b.district,40),enterprise:txt(b.enterprise,40),
        regNo:txt(b.regNo,20),paymentRef:x.ref,status:'NEW',note:'',created:Date.now()};
      x.customer=r.farmerName;db.req.push(r);save();return send(200,{ok:true}); 
    }
    return fail(404,'Not found');
  }catch(e){send(400,{error:e.message||'Request failed'})}
}).listen(PORT,()=>console.log('LiveAgric server on port '+PORT+' -> open /admin'));
