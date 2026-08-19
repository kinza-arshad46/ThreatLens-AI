/* ================= NAV SWITCHING ================= */
// Canvases that draw manually (not Chart.js) only ever measure their
// container's size once, at script load. If their page is hidden
// (display:none) at that moment, they measure 0x0 and never recover —
// this is why "Attack Graph" showed nothing before: it's not the default
// page, so its canvas initialized at zero size. Each such canvas registers
// a resize function here, keyed by page name, and switchToPage() calls it
// after the target page becomes visible so it can re-measure at real size.
window.__canvasResizers = {};

function switchToPage(target){
  navItems.forEach(b=>b.classList.toggle('active', b.dataset.page === target));
  pages.forEach(p=>p.classList.remove('active'));
  const pageEl = document.getElementById('page-' + target);
  if(!pageEl) return;
  pageEl.classList.add('active');
  // Wait one frame so the browser has applied display:block and the
  // container has a real width/height before any canvas re-measures it.
  requestAnimationFrame(()=>{
    if(window.__canvasResizers[target]) window.__canvasResizers[target]();
  });
}

const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');
navItems.forEach(btn=>{
  btn.addEventListener('click', ()=> switchToPage(btn.dataset.page));
});

/* ================= ICONS ================= */
if(window.lucide) lucide.createIcons();

/* ================= CLOCK ================= */
function tickClock(){
  const el = document.getElementById('clock');
  if(el) el.textContent = new Date().toLocaleTimeString('en-US', {hour12:false});
}
tickClock(); setInterval(tickClock, 1000);

/* ================= KPI COUNT-UP ================= */
document.querySelectorAll('.kpi-value[data-count]').forEach(el=>{
  const target = parseInt(el.dataset.count, 10);
  let current = 0;
  const step = Math.max(1, Math.floor(target/60));
  const timer = setInterval(()=>{
    current += step;
    if(current >= target){ current = target; clearInterval(timer); }
    el.textContent = current.toLocaleString();
  }, 16);
});

/* ================= LIVE EVENT FEED (SIMULATED) ================= */
const EVENT_TYPES = ['Failed Login','Login Success','API Request','Port Scan','Password Change','File Download','Suspicious API','DDoS Probe'];
const ATTACK_TYPES = ['Brute Force','DDoS','Web Attack','Port Scanning','Credential Stuffing','Normal'];
const LOCATIONS = ['Pakistan','USA','Germany','Russia','India','UAE','UK','Brazil'];
const USERS = ['U-1042','U-8821','U-3091','U-2115','U-7789','U-5502'];
const STATUS = ['Blocked','Allowed','Monitoring','Investigate'];

function randIP(){
  return `${rand(1,223)}.${rand(0,255)}.${rand(0,255)}.${rand(0,255)}`;
}
function rand(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
function pick(arr){ return arr[rand(0,arr.length-1)]; }
function nowTime(){ return new Date().toLocaleTimeString('en-US',{hour12:false}); }

function makeRow(cols){
  const tr = document.createElement('tr');
  tr.className = 'event-new';
  tr.innerHTML = cols;
  return tr;
}

function pushFeedRow(){
  const body = document.getElementById('feedBody');
  if(!body) return;
  const risk = rand(10,97);
  const riskClass = risk>90?'crit':risk>75?'high':risk>50?'med':'low';
  const statusVal = risk>85 ? 'Blocked' : pick(STATUS);
  const statusClass = statusVal==='Blocked'?'crit':statusVal==='Investigate'?'high':statusVal==='Monitoring'?'med':'low';
  const row = makeRow(`
    <td>${nowTime()}</td>
    <td>${pick(EVENT_TYPES)}</td>
    <td class="mono">${randIP()}</td>
    <td>${pick(USERS)}</td>
    <td class="risk ${riskClass}">${risk}%</td>
    <td><span class="status-pill ${statusClass}">${statusVal}</span></td>
  `);
  body.prepend(row);
  while(body.children.length > 7) body.removeChild(body.lastChild);
}
for(let i=0;i<6;i++) pushFeedRow();
setInterval(pushFeedRow, 2600);

function pushRealtimeRow(){
  const body = document.getElementById('realtimeBody');
  if(!body) return;
  const risk = rand(10,97);
  const riskClass = risk>90?'crit':risk>75?'high':risk>50?'med':'low';
  const statusVal = risk>85 ? 'Blocked' : pick(STATUS);
  const statusClass = statusVal==='Blocked'?'crit':statusVal==='Investigate'?'high':statusVal==='Monitoring'?'med':'low';
  const row = makeRow(`
    <td>${nowTime()}</td>
    <td>${pick(EVENT_TYPES)}</td>
    <td>${pick(USERS)}</td>
    <td class="mono">${randIP()}</td>
    <td>${pick(LOCATIONS)}</td>
    <td><span class="status-pill ${statusClass}">${statusVal}</span></td>
    <td class="risk ${riskClass}">${risk}%</td>
  `);
  body.prepend(row);
  while(body.children.length > 12) body.removeChild(body.lastChild);
  const eps = document.getElementById('eps');
  if(eps) eps.textContent = rand(900,1600).toLocaleString();
}
for(let i=0;i<10;i++) pushRealtimeRow();
setInterval(pushRealtimeRow, 1400);

/* ================= ROTATING THREAT GLOBE (CANVAS) ================= */
(function globe(){
  const canvas = document.getElementById('globeCanvas');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let W,H,R;
  function resize(){
    const parent = canvas.parentElement;
    W = canvas.width = parent.clientWidth * devicePixelRatio;
    H = canvas.height = parent.clientHeight * devicePixelRatio;
    canvas.style.width = parent.clientWidth+'px';
    canvas.style.height = parent.clientHeight+'px';
    R = Math.min(W,H) * 0.34;
  }
  resize();
  window.addEventListener('resize', resize);
  window.__canvasResizers['dashboard'] = resize;

  // generate points on sphere (lat/lon grid + random threat nodes)
  const gridPoints = [];
  for(let lat=-80; lat<=80; lat+=20){
    for(let lon=0; lon<360; lon+=20){
      gridPoints.push({lat, lon});
    }
  }
  const colors = ['#ff4d5a','#ffb020','#00ffa3','#3aa0ff','#b06bff'];
  const threatNodes = [];
  for(let i=0;i<14;i++){
    threatNodes.push({
      lat: rand(-60,60), lon: rand(0,359), color: colors[rand(0,colors.length-1)]
    });
  }
  // a few active arcs between threat nodes
  const arcs = [];
  for(let i=0;i<6;i++){
    arcs.push({ a: rand(0,threatNodes.length-1), b: rand(0,threatNodes.length-1), t: Math.random() });
  }

  function project(lat, lon, angle){
    const phi = lat * Math.PI/180;
    const theta = (lon + angle) * Math.PI/180;
    const x = Math.cos(phi) * Math.sin(theta);
    const y = Math.sin(phi);
    const z = Math.cos(phi) * Math.cos(theta);
    return {
      x: x * R,
      y: -y * R,
      z: z,
      visible: z > -0.15
    };
  }

  let angle = 0;
  function draw(){
    ctx.clearRect(0,0,W,H);
    const cx = W/2, cy = H/2;

    // outer glow ring
    const grad = ctx.createRadialGradient(cx,cy,R*0.7,cx,cy,R*1.25);
    grad.addColorStop(0,'rgba(0,255,163,0.10)');
    grad.addColorStop(1,'rgba(0,255,163,0)');
    ctx.fillStyle = grad;
    ctx.beginPath(); ctx.arc(cx,cy,R*1.25,0,Math.PI*2); ctx.fill();

    // core sphere fill
    ctx.beginPath(); ctx.arc(cx,cy,R,0,Math.PI*2);
    ctx.fillStyle = 'rgba(0,255,163,0.03)';
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,255,163,0.18)';
    ctx.lineWidth = 1*devicePixelRatio;
    ctx.stroke();

    // grid points (wireframe dots)
    gridPoints.forEach(p=>{
      const pr = project(p.lat, p.lon, angle);
      if(!pr.visible) return;
      const alpha = 0.15 + (pr.z+1)/2 * 0.35;
      ctx.beginPath();
      ctx.arc(cx+pr.x, cy+pr.y, 1*devicePixelRatio, 0, Math.PI*2);
      ctx.fillStyle = `rgba(0,255,163,${alpha})`;
      ctx.fill();
    });

    // threat nodes
    const projected = threatNodes.map(n=>({...n, p: project(n.lat, n.lon, angle)}));
    projected.forEach(n=>{
      if(!n.p.visible) return;
      const size = (2.4 + (n.p.z+1)*1.6) * devicePixelRatio;
      ctx.beginPath();
      ctx.arc(cx+n.p.x, cy+n.p.y, size, 0, Math.PI*2);
      ctx.fillStyle = n.color;
      ctx.shadowColor = n.color;
      ctx.shadowBlur = 8*devicePixelRatio;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // pulsing arcs between threat nodes
    arcs.forEach(arc=>{
      const a = projected[arc.a], b = projected[arc.b];
      if(!a || !b || !a.p.visible || !b.p.visible) return;
      const mx = (a.p.x + b.p.x)/2, my = (a.p.y + b.p.y)/2 - R*0.28;
      ctx.beginPath();
      ctx.moveTo(cx+a.p.x, cy+a.p.y);
      ctx.quadraticCurveTo(cx+mx, cy+my, cx+b.p.x, cy+b.p.y);
      ctx.strokeStyle = 'rgba(0,255,163,0.28)';
      ctx.lineWidth = 1*devicePixelRatio;
      ctx.stroke();

      arc.t += 0.006;
      if(arc.t > 1) arc.t = 0;
      const t = arc.t;
      const px = (1-t)*(1-t)*(cx+a.p.x) + 2*(1-t)*t*(cx+mx) + t*t*(cx+b.p.x);
      const py = (1-t)*(1-t)*(cy+a.p.y) + 2*(1-t)*t*(cy+my) + t*t*(cy+b.p.y);
      ctx.beginPath();
      ctx.arc(px, py, 2.2*devicePixelRatio, 0, Math.PI*2);
      ctx.fillStyle = '#eafff6';
      ctx.shadowColor = '#00ffa3';
      ctx.shadowBlur = 10*devicePixelRatio;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    angle += 0.18;
    requestAnimationFrame(draw);
  }
  draw();
})();

/* ================= CHART.JS GLOBAL DEFAULTS ================= */
if(window.Chart){
  Chart.defaults.color = '#7f9c93';
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.font.size = 11;
}

/* ---- Attack Distribution Donut (dashboard) ---- */
(function(){
  const el = document.getElementById('attackDonut');
  if(!el || !window.Chart) return;
  new Chart(el, {
    type:'doughnut',
    data:{
      labels:['Brute Force','DDoS','Web Attack','Port Scanning','Credential Stuffing','Exfiltration'],
      datasets:[{
        data:[35,20,18,15,8,4],
        backgroundColor:['#ff4d5a','#ffb020','#00ffa3','#3aa0ff','#b06bff','#e8d24a'],
        borderColor:'#0a1613', borderWidth:3, hoverOffset:6
      }]
    },
    options:{
      cutout:'72%',
      plugins:{ legend:{display:false}, tooltip:{backgroundColor:'#0c1815', borderColor:'rgba(0,255,163,0.2)', borderWidth:1} }
    }
  });
})();

/* ---- Attack Analytics page charts ---- */
(function(){
  const trendEl = document.getElementById('trendChart');
  if(trendEl && window.Chart){
    new Chart(trendEl, {
      type:'line',
      data:{
        labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
        datasets:[
          {label:'Brute Force', data:[40,52,48,61,58,70,65], borderColor:'#ff4d5a', backgroundColor:'rgba(255,77,90,0.08)', tension:0.4, fill:true},
          {label:'DDoS', data:[20,18,25,22,30,28,33], borderColor:'#ffb020', backgroundColor:'rgba(255,176,32,0.06)', tension:0.4, fill:true},
          {label:'Web Attack', data:[15,20,18,24,20,26,22], borderColor:'#00ffa3', backgroundColor:'rgba(0,255,163,0.06)', tension:0.4, fill:true}
        ]
      },
      options:{
        responsive:true, maintainAspectRatio:false,
        plugins:{legend:{position:'bottom', labels:{boxWidth:10, padding:16}}},
        scales:{ x:{grid:{color:'rgba(255,255,255,0.04)'}}, y:{grid:{color:'rgba(255,255,255,0.04)'}} }
      }
    });
  }
  const classEl = document.getElementById('classChart');
  if(classEl && window.Chart){
    new Chart(classEl, {
      type:'bar',
      data:{
        labels:['Brute Force','DDoS','Web Attack','Port Scan','Cred. Stuffing','Exfil'],
        datasets:[{ data:[187,102,91,76,52,21], backgroundColor:'#00ffa3', borderRadius:6, barThickness:26 }]
      },
      options:{
        responsive:true, maintainAspectRatio:false,
        plugins:{legend:{display:false}},
        scales:{ x:{grid:{display:false}}, y:{grid:{color:'rgba(255,255,255,0.04)'}} }
      }
    });
  }
})();

/* ---- UBA radar chart ---- */
(function(){
  const el = document.getElementById('ubaChart');
  if(!el || !window.Chart) return;
  new Chart(el, {
    type:'radar',
    data:{
      labels:['Login Hour Dev.','New Device','New IP','Request Volume','Failed Logins','Session Length'],
      datasets:[
        {label:'Baseline', data:[10,5,5,20,8,30], borderColor:'#3aa0ff', backgroundColor:'rgba(58,160,255,0.08)'},
        {label:'Current', data:[85,90,88,60,75,40], borderColor:'#ff4d5a', backgroundColor:'rgba(255,77,90,0.12)'}
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{position:'bottom', labels:{boxWidth:10, padding:14}}},
      scales:{ r:{ angleLines:{color:'rgba(255,255,255,0.06)'}, grid:{color:'rgba(255,255,255,0.06)'}, pointLabels:{color:'#7f9c93', font:{size:10}}, ticks:{display:false} } }
    }
  });
})();

/* ---- Forecast line chart ---- */
(function(){
  const el = document.getElementById('forecastChart');
  if(!el || !window.Chart) return;
  new Chart(el, {
    type:'line',
    data:{
      labels:['Now','+2h','+4h','+6h','+8h','+12h','+18h','+24h'],
      datasets:[{
        label:'Threat Probability',
        data:[55,63,71,75,80,83,86,89],
        borderColor:'#00ffa3', backgroundColor:'rgba(0,255,163,0.1)',
        tension:0.4, fill:true, pointBackgroundColor:'#00ffa3', pointRadius:4
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{ x:{grid:{color:'rgba(255,255,255,0.04)'}}, y:{min:0, max:100, grid:{color:'rgba(255,255,255,0.04)'}} }
    }
  });
})();

/* ================= ATTACK RELATIONSHIP GRAPH (CANVAS) ================= */
(function(){
  const canvas = document.getElementById('graphCanvas');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  function resize(){
    const parent = canvas.parentElement;
    canvas.width = parent.clientWidth * devicePixelRatio;
    canvas.height = parent.clientHeight * devicePixelRatio;
    canvas.style.width = parent.clientWidth+'px';
    canvas.style.height = parent.clientHeight+'px';
  }
  resize(); window.addEventListener('resize', resize);
  window.__canvasResizers['graph'] = resize;

  const center = {id:'192.168.1.105', type:'ip', color:'#ff4d5a'};
  const ring1 = [
    {id:'U-1042', type:'user', color:'#00ffa3'},
    {id:'U-8821', type:'user', color:'#00ffa3'},
    {id:'U-3091', type:'user', color:'#00ffa3'},
  ];
  const ring2 = [
    {id:'Dev-W10', type:'device', color:'#3aa0ff'},
    {id:'Dev-Mac', type:'device', color:'#3aa0ff'},
    {id:'Dev-Ubuntu', type:'device', color:'#3aa0ff'},
    {id:'Alert-778', type:'alert', color:'#ffb020'},
    {id:'Alert-779', type:'alert', color:'#ffb020'},
  ];

  function draw(){
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0,0,W,H);
    const cx = W/2, cy = H/2;
    const r1 = Math.min(W,H)*0.22, r2 = Math.min(W,H)*0.38;
    const t = performance.now()/1000;

    const p1 = ring1.map((n,i)=>{
      const a = (i/ring1.length)*Math.PI*2 + t*0.15;
      return {...n, x: cx+Math.cos(a)*r1, y: cy+Math.sin(a)*r1};
    });
    const p2 = ring2.map((n,i)=>{
      const a = (i/ring2.length)*Math.PI*2 - t*0.1;
      return {...n, x: cx+Math.cos(a)*r2, y: cy+Math.sin(a)*r2};
    });

    // edges center -> ring1
    ctx.lineWidth = 1.2*devicePixelRatio;
    p1.forEach(n=>{
      ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(n.x,n.y);
      ctx.strokeStyle = 'rgba(0,255,163,0.25)'; ctx.stroke();
    });
    // edges ring1 -> nearest ring2
    p1.forEach((a,i)=>{
      const b = p2[i % p2.length];
      const c = p2[(i+3) % p2.length];
      [b,c].forEach(n=>{
        ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(n.x,n.y);
        ctx.strokeStyle = 'rgba(255,255,255,0.06)'; ctx.stroke();
      });
    });

    function node(n, radius, label){
      ctx.beginPath();
      ctx.arc(n.x, n.y, radius, 0, Math.PI*2);
      ctx.fillStyle = n.color;
      ctx.shadowColor = n.color; ctx.shadowBlur = 12*devicePixelRatio;
      ctx.fill(); ctx.shadowBlur = 0;
      ctx.fillStyle = '#eafff6';
      ctx.font = `${11*devicePixelRatio}px Inter`;
      ctx.textAlign = 'center';
      ctx.fillText(label, n.x, n.y + radius + 14*devicePixelRatio);
    }

    node({x:cx,y:cy,color:center.color}, 12*devicePixelRatio, center.id);
    p1.forEach(n=> node(n, 8*devicePixelRatio, n.id));
    p2.forEach(n=> node(n, 6*devicePixelRatio, n.id));

    requestAnimationFrame(draw);
  }
  draw();
})();

/* ================= AI ANALYST CHAT (MOCK) ================= */
const RESPONSES = [
  "Based on current telemetry, this pattern is most consistent with a coordinated brute-force attempt originating from a small set of new IP addresses.",
  "This user's risk score is elevated primarily due to an off-hours login combined with a previously unseen device signature.",
  "Attack volume for this category increased relative to its 7-day baseline — largely driven by repeated authentication failures on the login endpoint.",
  "I'd recommend prioritizing investigation of the highest-risk user first, then reviewing the linked IP's full session history in the Attack Graph."
];
function wireChat(formId, inputId, windowId){
  const form = document.getElementById(formId);
  if(!form) return;
  form.addEventListener('submit', e=>{
    e.preventDefault();
    const input = document.getElementById(inputId);
    const win = document.getElementById(windowId);
    const val = input.value.trim();
    if(!val) return;
    const userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user';
    userMsg.innerHTML = `<p>${val.replace(/</g,'&lt;')}</p>`;
    win.appendChild(userMsg);
    input.value = '';
    win.scrollTop = win.scrollHeight;
    setTimeout(()=>{
      const botMsg = document.createElement('div');
      botMsg.className = 'chat-msg bot';
      botMsg.innerHTML = `<p>${pick(RESPONSES)}</p>`;
      win.appendChild(botMsg);
      win.scrollTop = win.scrollHeight;
    }, 650);
  });
}
wireChat('chatForm','chatInput','chatWindow');
wireChat('chatFormFull','chatInputFull','chatWindowFull');

/* ================= GENERIC DROPDOWN HELPERS ================= */
function openDropdown(panel){
  document.querySelectorAll('.dropdown-panel.show').forEach(p=>{ if(p!==panel) p.classList.remove('show'); });
  panel.classList.add('show');
}
function closeAllDropdowns(except=null){
  document.querySelectorAll('.dropdown-panel.show').forEach(p=>{ if(p!==except) p.classList.remove('show'); });
}
document.addEventListener('click', (e)=>{
  document.querySelectorAll('.dropdown-panel.show').forEach(panel=>{
    const trigger = panel.previousElementSibling;
    const wrap = panel.closest('.icon-btn-wrap, .search-wrap, .range-select-wrap');
    if(wrap && !wrap.contains(e.target)) panel.classList.remove('show');
  });
});
document.addEventListener('keydown', (e)=>{
  if(e.key === 'Escape') closeAllDropdowns();
});

/* ================= GLOBAL SEARCH ================= */
// A small realistic pool to search against — the same IPs/users already
// seen throughout the mocked data elsewhere in the dashboard, so search
// results feel consistent with everything else on screen.
const SEARCH_POOL = [
  {type:'ip', value:'192.168.1.105', meta:'Critical · Brute Force', goto:'analytics'},
  {type:'ip', value:'185.199.108.55', meta:'High · Web Attack', goto:'analytics'},
  {type:'ip', value:'203.0.113.45', meta:'High · Credential Stuffing', goto:'analytics'},
  {type:'ip', value:'198.51.100.23', meta:'Medium · DDoS', goto:'analytics'},
  {type:'ip', value:'198.51.100.32', meta:'High · Brute Force', goto:'analytics'},
  {type:'user', value:'U-1042', meta:'Risk 87% · Unusual', goto:'uba'},
  {type:'user', value:'U-8821', meta:'Risk 62% · Unusual', goto:'uba'},
  {type:'user', value:'U-3091', meta:'Risk 55% · Watch', goto:'uba'},
  {type:'user', value:'U-2115', meta:'Risk 38% · Normal', goto:'uba'},
  {type:'user', value:'U-7789', meta:'Risk 21% · Normal', goto:'uba'},
  {type:'device', value:'Dev-W10', meta:'Windows 10 · known', goto:'graph'},
  {type:'device', value:'Dev-Mac', meta:'macOS · known', goto:'graph'},
  {type:'device', value:'Dev-Ubuntu', meta:'Ubuntu · new device', goto:'graph'},
  {type:'threat', value:'Brute Force', meta:'187 events (24h)', goto:'analytics'},
  {type:'threat', value:'DDoS', meta:'102 events (24h)', goto:'analytics'},
  {type:'threat', value:'Web Attack', meta:'91 events (24h)', goto:'analytics'},
  {type:'threat', value:'Port Scanning', meta:'76 events (24h)', goto:'analytics'},
];
const SEARCH_ICON = {ip:'globe', user:'user-round', device:'laptop', threat:'shield-alert'};

(function setupGlobalSearch(){
  const input = document.getElementById('globalSearchInput');
  const panel = document.getElementById('searchResults');
  if(!input || !panel) return;

  function render(query){
    const q = query.trim().toLowerCase();
    if(!q){ panel.classList.remove('show'); return; }
    const matches = SEARCH_POOL.filter(item => item.value.toLowerCase().includes(q)).slice(0, 8);
    if(matches.length === 0){
      panel.innerHTML = `<div class="dd-empty">No matches for "${query.replace(/</g,'&lt;')}"</div>`;
    } else {
      panel.innerHTML = matches.map(item => `
        <button class="dd-result" data-goto="${item.goto}" data-value="${item.value}">
          <span class="dd-icon"><i data-lucide="${SEARCH_ICON[item.type]}"></i></span>
          <span>${item.value}</span>
          <span class="dd-meta">${item.meta}</span>
        </button>
      `).join('');
      if(window.lucide) lucide.createIcons();
    }
    openDropdown(panel);
  }

  input.addEventListener('input', ()=> render(input.value));
  input.addEventListener('focus', ()=> { if(input.value.trim()) render(input.value); });

  panel.addEventListener('click', (e)=>{
    const btn = e.target.closest('.dd-result');
    if(!btn) return;
    switchToPage(btn.dataset.goto);
    panel.classList.remove('show');
    input.value = '';
  });
})();

/* ================= NOTIFICATIONS DROPDOWN ================= */
(function setupNotifications(){
  const btn = document.getElementById('notifBtn');
  const panel = document.getElementById('notifPanel');
  if(!btn || !panel) return;

  const NOTIF_COLORS = {crit:'#ff4d5a', high:'#ffb020', med:'#e8d24a'};
  const notifications = [
    {level:'crit', title:'Critical alert — Brute Force from 192.168.1.105', time:'2 min ago'},
    {level:'crit', title:'DDoS traffic spike detected on API gateway', time:'9 min ago'},
    {level:'high', title:'U-8821 logged in from a new device', time:'24 min ago'},
    {level:'high', title:'Web Attack pattern flagged on server-7', time:'41 min ago'},
    {level:'med', title:'Port scan detected from 203.0.113.45', time:'1 hr ago'},
    {level:'med', title:'Threat forecast updated — 24h risk now 89%', time:'2 hr ago'},
  ];

  function render(){
    panel.innerHTML =
      `<div class="dd-section-label">Recent Notifications</div>` +
      notifications.map(n => `
        <div class="dd-notif">
          <span class="dd-dot" style="background:${NOTIF_COLORS[n.level]}"></span>
          <span class="dd-notif-body">
            <span class="dd-notif-title">${n.title}</span>
            <span class="dd-notif-time">${n.time}</span>
          </span>
        </div>
      `).join('');
  }
  render();

  btn.addEventListener('click', (e)=>{
    e.stopPropagation();
    if(panel.classList.contains('show')) panel.classList.remove('show');
    else openDropdown(panel);
  });
})();

/* ================= TOP-BAR SETTINGS ICON -> SETTINGS PAGE ================= */
(function setupTopSettingsBtn(){
  const btn = document.getElementById('topSettingsBtn');
  if(!btn) return;
  btn.addEventListener('click', ()=> switchToPage('settings'));
})();

/* ================= TIME RANGE DROPDOWN ================= */
(function setupRangeSelect(){
  const btn = document.getElementById('rangeSelectBtn');
  const menu = document.getElementById('rangeMenu');
  if(!btn || !menu) return;

  // Rough multipliers so switching ranges visibly changes the KPI numbers,
  // instead of only changing the label — small realism touch for a longer
  // window naturally showing a larger cumulative count.
  const RANGE_MULTIPLIERS = {
    'Last 1 Hour': 0.05, 'Last 6 Hours': 0.28, 'Last 24 Hours': 1,
    'Last 48 Hours': 1.9, 'Last 7 Days': 6.4,
  };
  const BASE_COUNTS = {events: 1248532, threats: 328, critical: 27};

  btn.addEventListener('click', (e)=>{
    e.stopPropagation();
    if(menu.classList.contains('show')) menu.classList.remove('show');
    else openDropdown(menu);
  });

  menu.addEventListener('click', (e)=>{
    const item = e.target.closest('.dropdown-item');
    if(!item) return;
    const range = item.dataset.range;
    btn.innerHTML = `${range} <i data-lucide="chevron-down"></i>`;
    if(window.lucide) lucide.createIcons();
    menu.classList.remove('show');

    const mult = RANGE_MULTIPLIERS[range] ?? 1;
    const kpiValues = document.querySelectorAll('.kpi-value[data-count]');
    const bases = [BASE_COUNTS.events, BASE_COUNTS.threats, BASE_COUNTS.critical];
    kpiValues.forEach((el, i)=>{
      const target = Math.max(1, Math.round(bases[i] * mult));
      el.dataset.count = target;
      let current = 0;
      const step = Math.max(1, Math.floor(target/40));
      const timer = setInterval(()=>{
        current += step;
        if(current >= target){ current = target; clearInterval(timer); }
        el.textContent = current.toLocaleString();
      }, 12);
    });
  });
})();

/* ================= "VIEW ALL" LINKS ================= */
document.querySelectorAll('[data-goto]').forEach(el=>{
  // Skip search-result buttons — those are wired separately above with
  // their own click handler on the panel (event delegation).
  if(el.closest('#searchResults')) return;
  el.addEventListener('click', (e)=>{
    e.preventDefault();
    switchToPage(el.dataset.goto);
  });
});
