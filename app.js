/* ============================================================
   研途日记 · 考研学习日记(数学 / 英语 / 408)
   纯原生实现:无框架、无外部请求(仅 GitHub API)
   安全模型:密码不离开设备;令牌用密码派生密钥 AES-GCM 加密
   ============================================================ */
'use strict';

/* ============ 0. 配置 ============ */
const CFG = {
  OWNER: 'jlshdsdk',
  SITE_REPO: 'kaoyan-diary',
  DATA_REPO: 'kaoyan-diary-data',
  BRANCH: 'main',
  ITER: 310000,               // PBKDF2 迭代次数
  API: 'https://api.github.com',
};
const MOODS = ['😄', '🙂', '😐', '😪', '🤯', '😤', '🥲', '💪'];
const TAGS = ['刷题', '背单词', '模考', '复盘', '错题整理', '状态好', '状态差', '进度落后', '有突破', '想放弃'];
const SUBJ = {
  math:    { name: '数学',  css: 'var(--math)' },
  english: { name: '英语',  css: 'var(--eng)'  },
  cs408:   { name: '408',   css: 'var(--cs)'   },
};
const QUOTES = [
  '每一个不曾刷题的日子,都是对梦想的辜负。',
  '数学是做出来的,不是看出来的。',
  '背了就忘?忘了再背。重复,是记忆之母。',
  '408 没有玄学,只有复习遍数。',
  '现在的每一分钟,都是十二月考场上的底气。',
  '不必追赶别人,只需超越昨天的自己。',
  '真题是最好的老师。',
  '坚持不下去的时候,就再坚持一下。',
  '单词量决定阅读的下限,长难句决定上限。',
  '政治可以晚一点开始,数学不能停一天。',
  '焦虑的时候,就去写一道题。',
  '此心安处是书房。',
  '上岸的人不是不累,只是累也在走。',
  '把计划写下来,把手机放远一点。',
  '今天的笔记,是明天最稳的安全感。',
  '错题不是敌人,是还没到手的分数。',
  '慢慢来,比较快。',
  '剩下的,交给十二月。',
  '与其熬夜赶进度,不如早起背单词。',
  '愿你合上笔盖的刹那,有侠客收剑入鞘的骄傲。',
];

/* ============ 1. 小工具 ============ */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
const pad2 = n => String(n).padStart(2, '0');
function dateKeyOf(d) { return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }
function todayKey() { return dateKeyOf(new Date()); }
function keyToDate(k) { const [y, m, d] = k.split('-').map(Number); return new Date(y, m - 1, d); }
function addDaysKey(k, n) { const d = keyToDate(k); d.setDate(d.getDate() + n); return dateKeyOf(d); }
const WEEK_CN = ['日', '一', '二', '三', '四', '五', '六'];
function weekCN(k) { return '周' + WEEK_CN[keyToDate(k).getDay()]; }
function fmtMD(k) { const d = keyToDate(k); return (d.getMonth() + 1) + '月' + d.getDate() + '日'; }
function fmtMin(m) {
  if (m <= 0) return '0 分钟';
  const h = Math.floor(m / 60), mm = m % 60;
  if (!h) return mm + ' 分钟';
  if (!mm) return h + ' 小时';
  return h + ' 小时 ' + mm + ' 分';
}
function fmtH(m) { return (m / 60).toFixed(1).replace(/\.0$/, '') + 'h'; }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

/* ============ 2. 编解码 ============ */
const _te = new TextEncoder(), _td = new TextDecoder();
function b64e(str) {
  const bytes = _te.encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000)
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
function b64d(b64) {
  const bin = atob(b64.replace(/\s/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return _td.decode(bytes);
}
function buf2hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function hex2buf(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
const randBytes = n => crypto.getRandomValues(new Uint8Array(n));

/* ============ 3. 密码学(PBKDF2 + AES-GCM) ============ */
async function deriveBits(password, saltHex, iter) {
  const base = await crypto.subtle.importKey('raw', _te.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: hex2buf(saltHex), iterations: iter },
    base, 512);
}
/* 用已有密钥上下文加密令牌(改令牌时无需再次输入密码) */
async function sealWithCtx(ctx, tokenStr) {
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, ctx.key, _te.encode(tokenStr));
  return { v: 1, iter: ctx.iter, salt: ctx.saltHex, iv: buf2hex(iv), ct: buf2hex(ct) };
}
async function makeCtx(password) {
  const saltHex = buf2hex(randBytes(16));
  const bits = await deriveBits(password, saltHex, CFG.ITER);
  return { saltHex, iter: CFG.ITER, key: await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']) };
}
async function sealToken(password, tokenStr) {
  const ctx = await makeCtx(password);
  return { enc: await sealWithCtx(ctx, tokenStr), ctx };
}
async function openToken(password, enc) {
  try {
    const bits = await deriveBits(password, enc.salt, enc.iter || CFG.ITER);
    const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hex2buf(enc.iv) }, key, hex2buf(enc.ct));
    return { token: _td.decode(pt), ctx: { saltHex: enc.salt, iter: enc.iter || CFG.ITER, key: await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']) } };
  } catch (e) { return null; }
}

/* ============ 4. GitHub API ============ */
class AuthError extends Error { constructor() { super('令牌已失效'); this.name = 'AuthError'; } }
async function gh(path, { method = 'GET', token, body, keepalive = false } = {}) {
  const headers = { Accept: 'application/vnd.github+json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body) headers['Content-Type'] = 'application/json';
  const r = await fetch(CFG.API + path, { method, headers, body: body ? JSON.stringify(body) : undefined, keepalive, cache: 'no-store' });
  return r;
}
async function getContents(repo, file, token) {
  const r = await gh(`/repos/${CFG.OWNER}/${repo}/contents/${file}`, { token });
  if (r.status === 404) return null;
  if (r.status === 401) throw new AuthError();
  if (!r.ok) {
    let m = ''; try { m = (await r.json()).message || ''; } catch (e) { }
    throw new Error('GitHub 读取失败 ' + r.status + (m ? ' · ' + m : ''));
  }
  const j = await r.json();
  if (j.content) return { sha: j.sha, data: JSON.parse(b64d(j.content)) };
  if (j.raw_url) { // 超大文件降级
    const rr = await fetch(j.raw_url, token ? { headers: { Authorization: 'Bearer ' + token } } : {});
    return { sha: j.sha, data: await rr.json() };
  }
  throw new Error('文件内容为空或格式异常');
}
async function putContents(repo, file, obj, sha, token, msg, keepalive = false) {
  const body = { message: msg || 'sync', content: b64e(JSON.stringify(obj)), branch: CFG.BRANCH };
  if (sha) body.sha = sha;
  const r = await gh(`/repos/${CFG.OWNER}/${repo}/contents/${file}`, { method: 'PUT', token, body, keepalive });
  if (r.status === 409 || r.status === 422) return { conflict: true };
  if (r.status === 401) throw new AuthError();
  if (!r.ok) {
    let m = ''; try { m = (await r.json()).message || ''; } catch (e) { }
    throw new Error('保存失败 ' + r.status + (m ? ' · ' + m : ''));
  }
  const j = await r.json();
  return { sha: j.content.sha };
}
async function deleteContents(repo, file, sha, token) {
  const r = await gh(`/repos/${CFG.OWNER}/${repo}/contents/${file}`, { method: 'DELETE', token, body: { message: 'delete ' + file, sha, branch: CFG.BRANCH } });
  if (r.status === 404) return; // 已经不存在
  if (!r.ok && r.status !== 401) throw new Error('删除失败 ' + r.status);
}
/* 账号表(公开仓库,密文)—— 登录时无需令牌 */
async function readAccounts(token) {
  try {
    const r = await gh(`/repos/${CFG.OWNER}/${CFG.SITE_REPO}/contents/accounts.json`, { token });
    if (r.status === 404) return { users: null, sha: null };
    if (r.ok) { const j = await r.json(); return { users: JSON.parse(b64d(j.content)), sha: j.sha }; }
  } catch (e) { if (token) throw e; }
  // 兜底:raw CDN(无 sha)
  const r2 = await fetch(`https://raw.githubusercontent.com/${CFG.OWNER}/${CFG.SITE_REPO}/${CFG.BRANCH}/accounts.json?_=${Date.now()}`, { cache: 'no-store' });
  if (r2.status === 404) return { users: null, sha: null };
  if (r2.ok) return { users: await r2.json(), sha: null };
  throw new Error('无法读取账号信息,请检查网络后重试');
}
async function validateToken(token) {
  try {
    const [r1, r2] = await Promise.all([
      gh(`/repos/${CFG.OWNER}/${CFG.DATA_REPO}`, { token }),
      gh(`/repos/${CFG.OWNER}/${CFG.SITE_REPO}`, { token }),
    ]);
    if (r1.status === 401 || r2.status === 401) return { ok: false, msg: '令牌无效或已过期,请重新生成' };
    if (r1.ok && r2.ok) return { ok: true };
    return { ok: false, msg: '令牌无法访问仓库(' + [r1.status, r2.status].join('/') + '),请确认已勾选 kaoyan-diary 与 kaoyan-diary-data 两个仓库,且 Contents 为 Read and write' };
  } catch (e) { return { ok: false, msg: '网络错误:' + e.message }; }
}
/* 带 3 次冲突重试的账号表修改(需登录令牌) */
async function mutateAccounts(token, mutator) {
  for (let i = 0; i < 3; i++) {
    const accs = await readAccounts(token);
    if (!accs.users) throw new Error('账号表不存在,请先完成初始化');
    const before = JSON.stringify(accs.users);
    mutator(accs.users);
    if (JSON.stringify(accs.users) === before) { S.accSha = accs.sha; return; }
    const r = await putContents(CFG.SITE_REPO, 'accounts.json', accs.users, accs.sha, token, 'chore: 账号管理更新');
    if (!r.conflict) { S.accSha = r.sha; return; }
  }
  throw new Error('保存冲突,请稍后重试');
}

/* ============ 5. 状态 ============ */
const S = {
  view: 'login', demo: false,
  user: null, role: null, note: null, token: null, encCtx: null,
  data: null, dataSha: null, dirty: false, saving: false, lastSync: 0,
  selDate: todayKey(), timerSub: localStorage.getItem('kyd_tsub') || 'math',
  today: todayKey(),
};
let T = null;           // 计时器 {sub,start,pausedMs,running,pausedAt}
let saveT = null, heavyT = null, retryT = null;

const lsDataKey = () => S.demo ? 'kyd_demo_data' : 'kyd_data_' + S.user;
function freshData(user) {
  return {
    version: 1, user,
    days: {},
    meta: {
      examDate: '2026-12-19', goalText: '计算机 · 数学一 · 英语一 · 408',
      goals: { math: 180, english: 120, cs408: 180 }, updatedAt: Date.now(),
    },
  };
}
function dayOf(k) {
  const days = S.data.days;
  if (!days[k]) days[k] = { text: '', mood: '', tags: [], minutes: { math: 0, english: 0, cs408: 0 }, createdAt: Date.now(), updatedAt: 0 };
  const d = days[k];
  if (!d.minutes) d.minutes = { math: 0, english: 0, cs408: 0 };
  if (!d.tags) d.tags = [];
  if (d.text === undefined) d.text = '';
  if (d.mood === undefined) d.mood = '';
  return d;
}
function dayTotal(d) { return d.minutes.math + d.minutes.english + d.minutes.cs408; }
function mergeData(base, over) {
  const out = JSON.parse(JSON.stringify(base || freshData(S.user)));
  const b = over || {};
  for (const k of Object.keys(b.days || {})) {
    const x = out.days[k], y = b.days[k];
    if (!x || ((y && y.updatedAt) || 0) >= ((x && x.updatedAt) || 0)) out.days[k] = y;
  }
  if (((b.meta && b.meta.updatedAt) || 0) > ((out.meta && out.meta.updatedAt) || 0)) out.meta = b.meta;
  return out;
}
function ensureMeta() {
  const f = freshData(S.user);
  S.data.meta = Object.assign({}, f.meta, S.data.meta || {});
  S.data.meta.goals = Object.assign({}, f.meta.goals, (S.data.meta && S.data.meta.goals) || {});
}

/* ============ 6. 视图切换 / 启动 ============ */
function showView(v) {
  S.view = v;
  $('#v-login').hidden = v !== 'login';
  $('#v-app').hidden = v !== 'app';
}
async function boot() {
  initTheme();
  bindEvents();
  renderMoodRow(); renderTagRow(); renderQuote();
  const creds = localStorage.getItem('kyd_creds');
  if (creds) {
    try {
      const c = JSON.parse(creds);
      S.user = c.user; S.role = c.role; S.token = c.token; S.note = c.note;
      await enterApp();
      return;
    } catch (e) { localStorage.removeItem('kyd_creds'); }
  }
  showView('login');
  // 首次使用自动弹向导
  try {
    const acc = await readAccounts();
    if (!acc.users) openModal('m-wizard');
    else if (acc.users && Object.keys(acc.users).length === 0) openModal('m-wizard');
  } catch (e) { /* 网络问题不阻塞登录页 */ }
  $('#li-user').focus();
}
async function enterApp() {
  showView('app');
  $('#demo-banner').hidden = !S.demo;
  $$('.admin-only').forEach(n => n.hidden = !(S.role === 'admin'));
  $('#user-name').textContent = S.note || S.user;
  $('#user-avatar').textContent = (S.note || S.user || '研').charAt(0).toUpperCase();
  if (S.demo) {
    S.data = JSON.parse(localStorage.getItem('kyd_demo_data') || 'null') || freshData('demo');
    ensureMeta(); S.selDate = todayKey();
    restoreTimer();
    renderAll(); setSync('demo');
    return;
  }
  setSync('loading');
  await loadUserData();
  if (S.view !== 'app') return; // 令牌失效等已跳回登录页
  restoreTimer();
  renderAll();
}
async function loadUserData() {
  try {
    const remote = await getContents(CFG.DATA_REPO, `data/${S.user}.json`, S.token);
    const cached = localStorage.getItem('kyd_data_' + S.user);
    if (remote) {
      S.data = remote.data;
      S.dataSha = remote.sha;
      if (cached) {
        const c = JSON.parse(cached);
        const merged = mergeData(S.data, c);
        if (JSON.stringify(merged) !== JSON.stringify(S.data)) { S.data = merged; S.dirty = true; }
      }
    } else {
      S.dataSha = null;
      if (cached) { S.data = JSON.parse(cached); S.dirty = true; }
      else S.data = freshData(S.user);
    }
    ensureMeta();
    if (S.dirty) setTimeout(() => syncNow(), 800);
  } catch (e) {
    if (e instanceof AuthError) { handleAuthFail(); return; }
    // 网络失败:先用本地缓存进入
    const cached = localStorage.getItem('kyd_data_' + S.user);
    S.data = cached ? JSON.parse(cached) : freshData(S.user);
    ensureMeta();
    setSync('offline');
    toast('网络不畅,已载入本机数据:' + e.message, 'err');
  }
}
function handleAuthFail() {
  localStorage.removeItem('kyd_creds');
  showView('login');
  toast('登录令牌已失效,请重新登录或让管理员更换令牌', 'err');
  if (S.role === 'admin') { $('#rc-user').value = S.user; openModal('m-recover'); }
}
function logout() {
  localStorage.removeItem('kyd_creds');
  T = null; localStorage.removeItem('kyd_timer_' + S.user);
  Object.assign(S, { user: null, role: null, token: null, data: null, dataSha: null, dirty: false, demo: false, note: null });
  stopClock();
  showView('login');
  setSync('idle');
  $('#li-pass').value = '';
  $('#li-user').focus();
}

/* ============ 7. 登录 / 演示 / 恢复 ============ */
async function doLogin(name, pass, remember) {
  const acc = await readAccounts();
  if (!acc || !acc.users || !Object.keys(acc.users).length) throw new Error('尚未初始化,请先完成初始化向导');
  const u = acc.users[name];
  if (!u) throw new Error('账号不存在');
  const res = await openToken(pass, u.enc);
  if (!res) throw new Error('密码错误');
  S.user = name; S.role = u.role || 'member'; S.note = u.note || '';
  S.token = res.token; S.encCtx = res.ctx;
  if (remember) localStorage.setItem('kyd_creds', JSON.stringify({ user: name, role: S.role, note: S.note, token: res.token }));
  await enterApp();
  toast('欢迎回来,' + (S.note || name) + ' 👋');
}
function enterDemo() {
  S.demo = true; S.user = '演示'; S.role = 'member';
  enterApp();
  toast('演示模式:数据仅保存在本机');
}
async function doRecover(name, pass, token) {
  const v = await validateToken(token);
  if (!v.ok) throw new Error(v.msg);
  const acc = await readAccounts(token);
  if (!acc || !acc.users || !Object.keys(acc.users).length) throw new Error('尚未初始化,请使用「初始化向导」');
  if (!acc.users[name]) throw new Error('账号「' + name + '」不存在');
  const { enc } = await sealToken(pass, token);
  await mutateAccounts(token, users => { users[name].enc = enc; users[name].needsReset = false; });
  S.user = name; S.role = acc.users[name].role || 'admin'; S.note = acc.users[name].note || '';
  S.token = token;
  const res2 = await openToken(pass, enc); S.encCtx = res2.ctx;
  localStorage.setItem('kyd_creds', JSON.stringify({ user: name, role: S.role, note: S.note, token }));
  await enterApp();
  toast('密码已重置并登录 ✅');
}

/* ============ 8. 数据同步 ============ */
function markDirtyLight() {
  if (S.demo) { localStorage.setItem('kyd_demo_data', JSON.stringify(S.data)); return; }
  localStorage.setItem('kyd_data_' + S.user, JSON.stringify(S.data));
  S.dirty = true; setSync('dirty');
  clearTimeout(saveT); saveT = setTimeout(() => syncNow(), 3500);
}
function markDirty() { markDirtyLight(); scheduleHeavy(); }
const scheduleHeavy = debounce(() => { if (S.view === 'app') { renderStats(); renderHeatmap(); renderArchive(); } }, 700);

async function syncNow(keepalive = false) {
  if (S.demo || !S.token || S.view !== 'app') return;
  if (S.saving) return;
  if (!S.dirty && !keepalive) return;
  S.saving = true; setSync('saving');
  clearTimeout(retryT);
  try {
    const msg = 'diary: ' + S.user + ' ' + todayKey();
    let res = await putContents(CFG.DATA_REPO, `data/${S.user}.json`, S.data, S.dataSha, S.token, msg, keepalive);
    if (res.conflict) {
      const remote = await getContents(CFG.DATA_REPO, `data/${S.user}.json`, S.token);
      const merged = mergeData(remote ? remote.data : freshData(S.user), S.data);
      res = await putContents(CFG.DATA_REPO, `data/${S.user}.json`, merged, remote ? remote.sha : null, S.token, 'diary: 合并同步 ' + S.user);
      S.data = merged; ensureMeta();
      localStorage.setItem('kyd_data_' + S.user, JSON.stringify(S.data));
      renderAll();
    }
    S.dataSha = res.sha; S.dirty = false; S.lastSync = Date.now();
    localStorage.setItem('kyd_data_' + S.user, JSON.stringify(S.data));
    setSync('ok'); updateDiaryHint();
  } catch (e) {
    if (e instanceof AuthError) { handleAuthFail(); return; }
    setSync('error');
    if (!keepalive) toast('同步失败,稍后自动重试:' + e.message, 'err');
    retryT = setTimeout(() => syncNow(), 30000);
  } finally {
    S.saving = false;
    if (S.dirty && !retryT) saveT = setTimeout(() => syncNow(), 5000);
  }
}
function setSync(state) {
  const dot = $('#sync-state .sync-dot'), txt = $('#sync-text');
  const cls = { ok: 'ok', saving: 'saving', dirty: 'dirty', offline: 'offline', error: 'error', demo: 'demo', loading: 'saving', idle: '' };
  dot.className = 'sync-dot ' + (cls[state] || '');
  const map = {
    ok: '已同步', saving: '同步中…', dirty: '待同步', offline: '离线 · 已存本机',
    error: '同步失败·点击重试', demo: '演示模式', loading: '连接中…', idle: '未登录',
  };
  txt.textContent = map[state] || '';
  updateDiaryHint();
}
function updateDiaryHint() {
  const h = $('#diary-hint');
  if (S.demo) { h.textContent = '仅存本机'; return; }
  h.textContent = $('#sync-text').textContent === '已同步' ? '已同步 ✓' : $('#sync-text').textContent;
}
function flushOnHide() {
  if (S.demo || !S.dirty || !S.token || S.view !== 'app') return;
  try {
    const payload = JSON.stringify(S.data);
    if (payload.length > 60000) return; // 超出 keepalive 限制,依赖常规同步
    const body = { message: 'diary: ' + S.user + ' ' + todayKey(), content: b64e(payload), branch: CFG.BRANCH };
    if (S.dataSha) body.sha = S.dataSha;
    fetch(`${CFG.API}/repos/${CFG.OWNER}/${CFG.DATA_REPO}/contents/data/${S.user}.json`, {
      method: 'PUT', keepalive: true,
      headers: { Authorization: 'Bearer ' + S.token, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) { }
}

/* ============ 9. 渲染总入口 ============ */
function renderAll() {
  renderHeader(); renderDiary(); renderTimeCard(); renderTimer();
  renderStats(); renderHeatmap(); renderArchive(); updateDiaryHint();
}
function renderHeader() {
  $('#brand-goal').textContent = S.data.meta.goalText || '计算机 · 数学一 · 英语一 · 408';
  const ex = S.data.meta.examDate ? keyToDate(S.data.meta.examDate) : null;
  const t0 = keyToDate(todayKey());
  const pill = $('#pill-countdown');
  if (ex) {
    const days = Math.round((ex - t0) / 86400000);
    if (days > 0) pill.textContent = '⏳ 距初试 ' + days + ' 天';
    else if (days === 0) pill.textContent = '🎯 今天初试,加油!';
    else pill.textContent = '🎓 初试已结束 · 研途不止';
  } else pill.textContent = '⏳ 未设置考试日期';
}
/* ---- 日记 ---- */
function renderMoodRow() {
  const box = $('#mood-row'); box.textContent = '';
  MOODS.forEach(m => { const b = el('button', 'mood-btn', m); b.type = 'button'; b.dataset.mood = m; box.append(b); });
}
function renderTagRow() {
  const box = $('#tag-row'); box.textContent = '';
  TAGS.forEach(t => { const b = el('button', 'tag-chip', t); b.type = 'button'; b.dataset.tag = t; box.append(b); });
}
function renderDiary() {
  const k = S.selDate, d = dayOf(k);
  const dd = keyToDate(k);
  $('#date-main').textContent = dd.getFullYear() + '年' + (dd.getMonth() + 1) + '月' + dd.getDate() + '日';
  $('#date-week').textContent = weekCN(k) + (k === todayKey() ? ' · 今天' : '');
  $('#btn-today').hidden = k === todayKey();
  $('#date-input').value = k;
  $('#diary-text').value = d.text || '';
  $('#word-count').textContent = countWords(d.text) + ' 字';
  $$('#mood-row .mood-btn').forEach(b => b.classList.toggle('on', b.dataset.mood === d.mood));
  $$('#tag-row .tag-chip').forEach(b => b.classList.toggle('on', d.tags.includes(b.dataset.tag)));
  autoGrow();
  $$('#heatmap .hm-cell').forEach(c => c.classList.toggle('sel', c.dataset.k === k));
}
function countWords(s) { return [...(s || '').replace(/\s/g, '')].length; }
function autoGrow() {
  const t = $('#diary-text');
  t.style.height = 'auto';
  t.style.height = Math.min(t.scrollHeight + 2, window.innerHeight * .6) + 'px';
}
function onDiaryInput() {
  const d = dayOf(S.selDate);
  d.text = $('#diary-text').value;
  d.updatedAt = Date.now();
  $('#word-count').textContent = countWords(d.text) + ' 字';
  markDirtyLight();
  scheduleHeavy();
}
/* ---- 打卡卡 ---- */
function renderTimeCard() {
  const k = S.selDate, d = dayOf(k), g = S.data.meta.goals;
  $('#card-time-title').textContent = fmtMD(k) + ' 学习打卡';
  $('#timer-box').hidden = k !== todayKey();
  $('#timer-box-hint').hidden = k === todayKey();
  const rows = $('#subject-rows'); rows.textContent = '';
  const total = dayTotal(d);
  for (const key of Object.keys(SUBJ)) {
    const row = el('div', 'subj-row');
    row.dataset.sub = key;
    const name = el('div', 'subj-name');
    const dot = el('i'); dot.style.background = SUBJ[key].css;
    name.append(dot, el('span', '', SUBJ[key].name));
    const bar = el('div', 'subj-bar');
    const fill = el('i'); fill.style.background = SUBJ[key].css;
    const pct = g[key] ? clamp(d.minutes[key] / g[key] * 100, 0, 100) : 0;
    fill.style.width = pct + '%';
    bar.append(fill);
    const mins = el('div', 'subj-mins');
    [['-15', 'minus'], ['+15', ''], ['+30', ''], ['+60', '']].forEach(([lab, cls]) => {
      const b = el('button', 'qbtn ' + cls, lab.replace('-', '−'));
      b.type = 'button'; b.dataset.d = lab; b.dataset.sub = key;
      mins.append(b);
    });
    const num = el('span', 'mins-num', liveMinutes(key) + ' 分');
    num.title = '点击直接输入分钟数'; num.dataset.sub = key;
    mins.append(num);
    row.append(name, bar, mins);
    rows.append(row);
  }
  const goalTotal = (g.math || 0) + (g.english || 0) + (g.cs408 || 0);
  $('#day-goal-fill').style.width = (goalTotal ? clamp(total / goalTotal * 100, 0, 100) : 0) + '%';
  $('#day-goal-text').textContent = goalTotal
    ? (total >= goalTotal ? '🎉 已达成今日目标!' : `距 ${fmtMD(k)} 目标还差 ${goalTotal - total} 分钟(目标 ${fmtH(goalTotal)})`)
    : '未设置每日目标';
  $('#today-total-badge').textContent = '合计 ' + fmtMin(total);
}
function liveMinutes(sub) {
  const d = dayOf(S.selDate);
  let v = d.minutes[sub] || 0;
  if (T && T.running && T.sub === sub && S.selDate === todayKey()) v += Math.floor((Date.now() - T.start - T.pausedMs) / 60000);
  return v;
}
function addMinutes(sub, delta, base) {
  const d = dayOf(S.selDate);
  d.minutes[sub] = clamp(base !== undefined ? base : (d.minutes[sub] || 0) + delta, 0, 1440);
  d.updatedAt = Date.now();
  markDirty();
  renderTimeCard();
}
function editMins(sub, span) {
  const d = dayOf(S.selDate);
  const input = document.createElement('input');
  input.type = 'number'; input.min = '0'; input.max = '1440'; input.value = d.minutes[sub] || 0;
  span.textContent = ''; span.append(input);
  input.focus(); input.select();
  let done = false;
  const commit = ok => {
    if (done) return; done = true;
    if (ok && input.value !== '') addMinutes(sub, 0, clamp(parseInt(input.value, 10) || 0, 0, 1440));
    else renderTimeCard();
  };
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') commit(true);
    if (e.key === 'Escape') commit(false);
    e.stopPropagation();
  });
  input.addEventListener('blur', () => commit(true));
}
/* ---- 计时器 ---- */
function renderTimer() {
  const disp = $('#timer-display'), status = $('#timer-status');
  const main = $('#btn-timer-main'), stop = $('#btn-timer-stop'), dis = $('#btn-timer-discard');
  const chips = $('#timer-subjects'); chips.textContent = '';
  for (const key of Object.keys(SUBJ)) {
    const c = el('button', 'tsub' + (S.timerSub === key ? ' on' : ''), SUBJ[key].name);
    c.type = 'button'; c.dataset.s = key;
    c.style.pointerEvents = (T && T.running) ? 'none' : '';
    chips.append(c);
  }
  if (!T) {
    disp.textContent = '00:00'; disp.classList.remove('running');
    status.textContent = '选择科目,开始专注';
    main.textContent = '开始计时'; stop.hidden = true; dis.hidden = true;
  } else {
    const ms = T.running ? Date.now() - T.start - T.pausedMs : T.pausedAt - T.start - T.pausedMs;
    disp.textContent = fmtClock(ms);
    disp.classList.toggle('running', T.running);
    status.textContent = T.running
      ? '专注中 · ' + SUBJ[T.sub].name + (ms > 6 * 3600e3 ? ' · 计时偏长,请确认' : '')
      : '已暂停 · ' + SUBJ[T.sub].name;
    main.textContent = T.running ? '暂停' : '继续';
    stop.hidden = false; dis.hidden = false;
  }
}
function fmtClock(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), ss = s % 60;
  return (h ? h + ':' + pad2(m) : pad2(m)) + ':' + pad2(ss);
}
function startTimer() {
  T = { sub: S.timerSub, start: Date.now(), pausedMs: 0, running: true, pausedAt: 0 };
  persistTimer(); renderTimer(); startClock();
}
function toggleTimer() {
  if (!T) return startTimer();
  if (T.running) { T.running = false; T.pausedAt = Date.now(); }
  else { T.pausedMs += Date.now() - T.pausedAt; T.running = true; }
  persistTimer(); renderTimer(); renderTimeCard();
}
async function stopTimer() {
  if (!T) return;
  const ms = T.running ? Date.now() - T.start - T.pausedMs : T.pausedAt - T.start - T.pausedMs;
  let mins = Math.round(ms / 60000);
  if (mins < 1) mins = 1;
  if (mins > 720) {
    const ok = await confirmBox({ title: '计时较长', text: `本次计时 ${fmtMin(mins)},超过 12 小时,确认全部计入「${SUBJ[T.sub].name}」吗?`, okText: '全部计入' });
    if (!ok) return;
    mins = 720;
  }
  const sub = T.sub;
  T = null; persistTimer(); stopClock();
  S.selDate = todayKey();
  addMinutes(sub, mins);
  renderTimer();
  toast(`已计入「${SUBJ[sub].name}」${fmtMin(mins)} ✅`);
}
async function discardTimer() {
  if (!T) return;
  const ms = T.running ? Date.now() - T.start - T.pausedMs : T.pausedAt - T.start - T.pausedMs;
  const mins = Math.floor(ms / 60000);
  if (mins >= 1) {
    const ok = await confirmBox({ title: '放弃计时', text: `确定放弃本次计时吗?已进行 ${fmtMin(mins)},不会被记录。`, okText: '放弃' });
    if (!ok) return;
  }
  T = null; persistTimer(); stopClock(); renderTimer();
}
function persistTimer() {
  if (T) localStorage.setItem('kyd_timer_' + S.user, JSON.stringify(T));
  else localStorage.removeItem('kyd_timer_' + S.user);
}
let clockI = null;
function startClock() { if (!clockI) clockI = setInterval(() => { renderTimer(); if (T && T.running) renderTimeCard(); }, 1000); }
function stopClock() { clearInterval(clockI); clockI = null; }
function restoreTimer() {
  const raw = localStorage.getItem('kyd_timer_' + S.user);
  if (!raw) { renderTimer(); return; }
  try {
    T = JSON.parse(raw);
    const ms = T.running ? Date.now() - T.start - T.pausedMs : 0;
    if (T.running && ms > 6 * 3600e3) { T.running = false; T.pausedAt = Date.now(); toast('检测到上次计时已超过 6 小时,已自动暂停,请确认后计入或放弃', 'err'); }
    else if (T.running) toast('已恢复上次计时(' + SUBJ[T.sub].name + '),正在继续 ⏱️');
  } catch (e) { T = null; }
  if (T) startClock();
  renderTimer();
}
/* ---- 统计 ---- */
function renderStats() {
  const days = S.data.days, tk = todayKey();
  const t = dayOf(tk);
  let todayMin = dayTotal(t);
  if (T && T.running) todayMin += Math.floor((Date.now() - T.start - T.pausedMs) / 60000);
  $('#st-today').textContent = todayMin;
  // 本周(周一至今)
  const now = keyToDate(tk); const monday = new Date(now); monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
  let weekMin = 0;
  for (let d = new Date(monday); dateKeyOf(d) <= tk; d.setDate(d.getDate() + 1)) {
    const x = days[dateKeyOf(d)]; if (x) weekMin += dayTotal(x);
  }
  $('#st-week').textContent = (weekMin / 60).toFixed(1);
  $('#st-streak').textContent = calcStreak();
  let totalMin = 0;
  for (const k in days) totalMin += dayTotal(days[k]);
  $('#st-total').textContent = (totalMin / 60).toFixed(1);
  renderBars(); renderDonut();
}
function isActive(k) {
  const x = S.data.days[k];
  return !!(x && (dayTotal(x) > 0 || (x.text || '').trim()));
}
function calcStreak() {
  let n = 0; const d = keyToDate(todayKey());
  if (!isActive(dateKeyOf(d))) d.setDate(d.getDate() - 1);
  while (isActive(dateKeyOf(d))) { n++; d.setDate(d.getDate() - 1); }
  return n;
}
function renderBars() {
  const box = $('#bars-7d'); box.textContent = '';
  const g = S.data.meta.goals, goalTotal = (g.math || 0) + (g.english || 0) + (g.cs408 || 0);
  const list = [];
  let maxV = Math.max(goalTotal, 60);
  for (let i = 6; i >= 0; i--) {
    const k = addDaysKey(todayKey(), -i);
    const x = S.data.days[k];
    let v = x ? dayTotal(x) : 0;
    if (i === 0 && T && T.running) v += Math.floor((Date.now() - T.start - T.pausedMs) / 60000);
    maxV = Math.max(maxV, v);
    list.push({ k, v, m: x ? x.minutes : { math: 0, english: 0, cs408: 0 } });
  }
  list.forEach((it, idx) => {
    const col = el('div', 'bar-col');
    if (it.v > 0) col.append(el('span', 'bar-val', fmtH(it.v)));
    const bar = el('div', 'bar');
    bar.style.height = clamp(it.v / maxV * 100, 2, 100) + '%';
    for (const key of ['math', 'english', 'cs408']) {
      if (!it.m[key]) continue;
      const seg = el('i', 'b-' + (key === 'math' ? 'math' : key === 'english' ? 'eng' : 'cs'));
      seg.style.height = (it.m[key] / Math.max(it.v, 1) * 100) + '%';
      bar.append(seg);
    }
    col.append(bar);
    const d = keyToDate(it.k);
    const lab = el('span', 'bar-day' + (idx === 6 ? ' today' : ''), idx === 6 ? '今' : WEEK_CN[d.getDay()]);
    col.append(lab);
    box.append(col);
  });
}
function renderDonut() {
  const donut = $('#donut-week'), center = $('#donut-center'), lg = $('#donut-legend');
  const now = keyToDate(todayKey()); const monday = new Date(now); monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
  const sum = { math: 0, english: 0, cs408: 0 };
  for (let d = new Date(monday); dateKeyOf(d) <= todayKey(); d.setDate(d.getDate() + 1)) {
    const x = S.data.days[dateKeyOf(d)]; if (!x) continue;
    sum.math += x.minutes.math || 0; sum.english += x.minutes.english || 0; sum.cs408 += x.minutes.cs408 || 0;
  }
  const tot = sum.math + sum.english + sum.cs408;
  lg.textContent = '';
  const items = [['math', sum.math], ['english', sum.english], ['cs408', sum.cs408]];
  let acc = 0;
  if (tot > 0) {
    const stops = [];
    items.forEach(([key, v]) => {
      const from = acc / tot * 100; acc += v;
      stops.push(`${SUBJ[key].css} ${from.toFixed(2)}% ${(acc / tot * 100).toFixed(2)}%`);
    });
    donut.style.background = `conic-gradient(${stops.join(',')})`;
    center.textContent = fmtH(tot);
  } else { donut.style.background = ''; center.textContent = '--'; }
  items.forEach(([key, v]) => {
    const row = el('div');
    const i = el('i'); i.style.background = SUBJ[key].css;
    row.append(i, document.createTextNode(SUBJ[key].name), el('b', '', ' ' + fmtH(v)));
    lg.append(row);
  });
}
/* ---- 热力图 ---- */
function renderHeatmap() {
  const grid = $('#heatmap'), months = $('#hm-months');
  const tk = todayKey();
  const end = keyToDate(tk);
  let start = new Date(end); start.setDate(start.getDate() - 364);
  start.setDate(start.getDate() - ((start.getDay() + 6) % 7)); // 对齐周一
  const fragParts = [], monthParts = [];
  const cellOf = k => {
    const d = S.data.days[k];
    const m = d ? dayTotal(d) : 0;
    const lvl = m <= 0 ? 0 : m < 60 ? 1 : m < 180 ? 2 : m < 360 ? 3 : 4;
    return `<i class="hm-cell l${lvl}${k === S.selDate ? ' sel' : ''}" data-k="${k}"></i>`;
  };
  let i = 0, lastMonth = -1;
  for (let d = new Date(start); ; d.setDate(d.getDate() + 1)) {
    const k = dateKeyOf(d);
    if (d.getDay() === 1) { // 每列从周一开始
      const mo = d.getMonth();
      if (mo !== lastMonth) {
        lastMonth = mo;
        const x = Math.floor(i / 7) * 16;
        if (x < 53 * 16 - 32) monthParts.push(`<span style="left:${x}px">${mo + 1}月</span>`);
      }
    }
    fragParts.push(cellOf(k));
    i++;
    if (k === tk) break;
  }
  grid.innerHTML = fragParts.join('');
  months.innerHTML = monthParts.join('');
}
function heatTip(k, cell) {
  const tip = $('#tooltip');
  const d = S.data.days[k];
  const tt = el('div');
  const title = el('b', '', `${fmtMD(k)} ${weekCN(k)}`);
  tt.append(title);
  const total = d ? dayTotal(d) : 0;
  tt.append(el('div', '', total > 0 ? '学习 ' + fmtMin(total) : '未记录学习时长'));
  if (d && total > 0) {
    const row = el('div', 'tt-sub');
    [['math', d.minutes.math], ['english', d.minutes.english], ['cs408', d.minutes.cs408]].forEach(([key, v]) => {
      if (v > 0) row.append(el('span', '', `${SUBJ[key].name} ${fmtH(v)}`));
    });
    tt.append(row);
  }
  tt.append(el('div', '', d && (d.text || '').trim() ? '📝 已写日记' : '未写日记'));
  tip.textContent = ''; tip.append(tt);
  tip.hidden = false;
  const r = cell.getBoundingClientRect();
  tip.style.left = '0px'; tip.style.top = '0px';
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  let x = clamp(r.left + r.width / 2 - tw / 2, 8, window.innerWidth - tw - 8);
  let y = r.top - th - 8;
  if (y < 8) y = r.bottom + 8;
  tip.style.left = x + 'px'; tip.style.top = y + 'px';
}
/* ---- 往期日记 ---- */
let archShown = 60;
function renderArchive() {
  const box = $('#arch-list'), q = $('#arch-search').value.trim().toLowerCase();
  box.textContent = '';
  const keys = Object.keys(S.data.days)
    .filter(k => { const d = S.data.days[k]; return (d.text || '').trim() || dayTotal(d) > 0; })
    .sort((a, b) => b.localeCompare(a));
  const filtered = q ? keys.filter(k => (S.data.days[k].text || '').toLowerCase().includes(q)) : keys;
  $('#arch-more').hidden = filtered.length <= archShown;
  const shown = filtered.slice(0, archShown);
  if (!shown.length) { box.append(el('div', 'arch-empty', q ? '没有匹配的日记 🔍' : '还没有记录,从今天开始吧 ✍️')); return; }
  shown.forEach(k => {
    const d = S.data.days[k];
    const item = el('div', 'arch-item'); item.dataset.k = k;
    const dt = el('div', 'arch-date');
    const dd = keyToDate(k);
    dt.append(el('b', '', String(dd.getDate())), el('span', '', (dd.getMonth() + 1) + '月 ' + WEEK_CN[dd.getDay()]));
    const mid = el('div', 'arch-mid');
    const txt = (d.text || '').trim();
    mid.append(el('p', 'arch-ex', txt || '(只记录了学习时长)'));
    const meta = el('div', 'arch-meta');
    if (dayTotal(d) > 0) meta.append(el('span', 'arch-pill p-time', fmtH(dayTotal(d))));
    (d.tags || []).slice(0, 3).forEach(t => meta.append(el('span', 'arch-pill', t)));
    mid.append(meta);
    item.append(dt, mid);
    if (d.mood) item.append(el('span', 'arch-mood', d.mood));
    item.addEventListener('click', () => {
      S.selDate = k;
      renderDiary(); renderTimeCard();
      $('#card-diary').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    box.append(item);
  });
}
/* ---- 每日一句 ---- */
function renderQuote() {
  const now = new Date();
  const doy = Math.floor((now - new Date(now.getFullYear(), 0, 0)) / 864e5);
  $('#quote-text').textContent = QUOTES[doy % QUOTES.length];
}

/* ============ 10. 设置 / 账号管理 ============ */
function openSettings(tab) {
  fillSetAccount(); fillSetSync(); fillPrefs();
  if (S.role === 'admin') renderAdminList();
  switchTab(tab || 'account');
  openModal('m-settings');
}
function switchTab(name) {
  $$('.set-tab').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
  $$('.set-pane').forEach(p => p.hidden = p.dataset.pane !== name);
}
function fillSetAccount() {
  const box = $('#set-user-info'); box.textContent = '';
  const add = (k, v) => { const r = el('div', 'info-row'); r.append(el('span', '', k), el('b', '', v)); box.append(r); };
  add('账号', S.user);
  add('身份', S.role === 'admin' ? '管理员' : '成员');
  add('同步仓库', CFG.OWNER + '/' + CFG.DATA_REPO + '(私有)');
  add('账号表', CFG.OWNER + '/' + CFG.SITE_REPO + ' · accounts.json(密文)');
  add('令牌', S.demo ? '演示模式无令牌' : '已配置 ✓(加密保存)');
}
function fillSetSync() {
  const box = $('#set-sync-info'); box.textContent = '';
  const nDays = Object.keys(S.data.days).length;
  const size = JSON.stringify(S.data).length;
  const add = (k, v) => { const r = el('div', 'info-row'); r.append(el('span', '', k), el('b', '', v)); box.append(r); };
  add('已记录天数', nDays + ' 天');
  add('数据大小', (size / 1024).toFixed(1) + ' KB');
  add('上次同步', S.lastSync ? new Date(S.lastSync).toLocaleString('zh-CN') : '本次会话尚未同步');
  $('#set-token').value = '';
}
function fillPrefs() {
  $('#set-exam-date').value = S.data.meta.examDate || '';
  $('#set-goal-text').value = S.data.meta.goalText || '';
  const g = S.data.meta.goals;
  $('#set-goal-math').value = g.math; $('#set-goal-eng').value = g.english; $('#set-goal-cs').value = g.cs408;
}
function savePrefs() {
  const exam = $('#set-exam-date').value;
  if (exam && !/^\d{4}-\d{2}-\d{2}$/.test(exam)) return toast('考试日期格式不对', 'err');
  S.data.meta.examDate = exam || '2026-12-19';
  S.data.meta.goalText = $('#set-goal-text').value.trim() || '计算机 · 数学一 · 英语一 · 408';
  S.data.meta.goals = {
    math: clamp(parseInt($('#set-goal-math').value, 10) || 0, 0, 720),
    english: clamp(parseInt($('#set-goal-eng').value, 10) || 0, 0, 720),
    cs408: clamp(parseInt($('#set-goal-cs').value, 10) || 0, 0, 720),
  };
  S.data.meta.updatedAt = Date.now();
  markDirty(); renderHeader(); renderTimeCard(); renderStats();
  toast('偏好已保存 ✅');
}
async function changePassword() {
  const oldP = $('#pw-old').value, n1 = $('#pw-new').value, n2 = $('#pw-new2').value;
  const err = $('#pw-err');
  err.hidden = true;
  if (n1.length < 8) { err.textContent = '新密码至少 8 位'; err.hidden = false; return; }
  if (n1 !== n2) { err.textContent = '两次输入的新密码不一致'; err.hidden = false; return; }
  try {
    if (!S.demo) {
      const check = await openToken(oldP, (await readAccounts(S.token)).users[S.user].enc);
      if (!check) { err.textContent = '当前密码不正确'; err.hidden = false; return; }
      const { enc, ctx } = await sealToken(n1, S.token);
      await mutateAccounts(S.token, users => { users[S.user].enc = enc; });
      S.encCtx = ctx;
      localStorage.setItem('kyd_creds', JSON.stringify({ user: S.user, role: S.role, note: S.note, token: S.token }));
    }
    $('#pw-old').value = $('#pw-new').value = $('#pw-new2').value = '';
    toast('密码修改成功,本机已记住新凭据 ✅');
  } catch (e) {
    err.textContent = e.message; err.hidden = false;
  }
}
function renderAdminList() {
  const box = $('#admin-list');
  box.textContent = '加载中…';
  readAccounts(S.token).then(acc => {
    box.textContent = '';
    if (!acc || !acc.users) { box.append(el('div', 'arch-empty', '账号表不存在')); return; }
    const names = Object.keys(acc.users).sort((a, b) => (acc.users[a].createdAt || 0) - (acc.users[b].createdAt || 0));
    names.forEach(name => {
      const u = acc.users[name];
      const item = el('div', 'admin-item');
      const av = el('span', 'avatar', (u.note || name).charAt(0).toUpperCase());
      const nameBox = el('div');
      const nb = el('div', 'ai-name', name + (u.note ? '' : ''));
      if (u.note) nb.append(el('small', '', u.note));
      nameBox.append(nb);
      const meta = el('div');
      meta.append(el('span', 'ai-role' + (u.role === 'admin' ? '' : ' member'), u.role === 'admin' ? '管理员' : '成员'));
      if (u.needsReset) meta.append(el('span', 'ai-warn', ' · 需重置密码'));
      nameBox.append(meta);
      const btns = el('div', 'ai-btns');
      const bReset = el('button', 'btn btn-ghost', '重置密码'); bReset.type = 'button';
      bReset.onclick = async () => {
        const np = await confirmBox({
          title: '重置「' + name + '」的密码',
          text: '请设置新的初始密码(至少 8 位),设置后请告知对方登录并自行修改。',
          input: { label: '新密码', type: 'text', value: '' }, okText: '重置',
        });
        if (!np) return;
        if (np.length < 8) return toast('密码至少 8 位', 'err');
        try {
          const { enc } = await sealToken(np, S.token);
          await mutateAccounts(S.token, users => { users[name].enc = enc; users[name].needsReset = false; });
          toast('已重置「' + name + '」的密码 ✅');
          renderAdminList();
        } catch (e) { toast(e.message, 'err'); }
      };
      const bDel = el('button', 'btn btn-danger-ghost', '删除'); bDel.type = 'button';
      bDel.onclick = async () => {
        if (name === S.user) return toast('不能删除当前登录的账号', 'err');
        const ok = await confirmBox({ title: '删除账号', text: `确定删除「${name}」吗?其全部日记数据将一并删除,不可恢复!`, okText: '删除' });
        if (!ok) return;
        try {
          await mutateAccounts(S.token, users => { delete users[name]; });
          try {
            const f = await getContents(CFG.DATA_REPO, `data/${name}.json`, S.token);
            if (f) await deleteContents(CFG.DATA_REPO, `data/${name}.json`, f.sha, S.token);
          } catch (e) { if (!(e instanceof AuthError)) console.warn(e); }
          toast('已删除「' + name + '」');
          renderAdminList();
        } catch (e) { toast(e.message, 'err'); }
      };
      btns.append(bReset, bDel);
      item.append(av, nameBox, btns);
      box.append(item);
    });
  }).catch(e => { box.textContent = ''; box.append(el('div', 'arch-empty', '加载失败:' + e.message)); });
}
async function adminCreateUserReal() {
  const name = $('#au-user').value.trim(), pass = $('#au-pass').value, note = $('#au-note').value.trim();
  const err = $('#au-err'); err.hidden = true;
  const fail = m => { err.textContent = m; err.hidden = false; };
  if (!/^[a-zA-Z0-9_-]{2,20}$/.test(name)) return fail('用户名需 2-20 位,仅限字母/数字/_/-');
  if (pass.length < 8) return fail('初始密码至少 8 位');
  try {
    // 先检查是否存在
    const acc = await readAccounts(S.token);
    if (acc.users[name]) return fail('账号「' + name + '」已存在');
    const { enc } = await sealToken(pass, S.token);
    await mutateAccounts(S.token, users => { users[name] = { note, role: 'member', createdAt: Date.now(), enc }; });
    $('#au-user').value = $('#au-pass').value = $('#au-note').value = '';
    toast('账号「' + name + '」创建成功,把用户名和初始密码告诉对方吧 ✅');
    renderAdminList();
  } catch (e) { fail('创建失败:' + e.message); }
}
async function replaceToken() {
  if (S.demo) return toast('演示模式无需令牌');
  const token = $('#set-token').value.trim();
  const err = $('#tk-err'); err.hidden = true;
  if (!token) { err.textContent = '请粘贴新令牌'; err.hidden = false; return; }
  const v = await validateToken(token);
  if (!v.ok) { err.textContent = v.msg; err.hidden = false; return; }
  try {
    const enc = await sealWithCtx(S.encCtx, token);
    let others = 0;
    await mutateAccounts(S.token, users => {
      for (const name of Object.keys(users)) {
        if (name === S.user) users[name].enc = enc;
        else { users[name].needsReset = true; others++; }
      }
    });
    S.token = token;
    localStorage.setItem('kyd_creds', JSON.stringify({ user: S.user, role: S.role, note: S.note, token }));
    $('#set-token').value = '';
    fillSetAccount();
    toast('令牌已更换 ✅' + (others ? `(其他 ${others} 个账号需重置密码)` : ''));
  } catch (e) { err.textContent = e.message; err.hidden = false; }
}
function exportData() {
  const blob = new Blob([JSON.stringify(S.data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `研途日记-${S.user}-${todayKey()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
  toast('备份已导出 📦');
}
function importData(file) {
  const fr = new FileReader();
  fr.onload = async () => {
    try {
      const obj = JSON.parse(fr.result);
      if (!obj || typeof obj !== 'object' || !obj.days) throw new Error('不是有效的备份文件');
      const okKeys = /^\d{4}-\d{2}-\d{2}$/;
      for (const k of Object.keys(obj.days)) {
        if (!okKeys.test(k)) { delete obj.days[k]; continue; }
        const d = obj.days[k];
        d.text = String(d.text || '').slice(0, 30000);
        if (!d.minutes || typeof d.minutes !== 'object') d.minutes = { math: 0, english: 0, cs408: 0 };
        for (const s of Object.keys(d.minutes)) d.minutes[s] = clamp(parseInt(d.minutes[s], 10) || 0, 0, 1440);
      }
      const merged = mergeData(S.data, obj);
      S.data = merged; ensureMeta();
      markDirty(); renderAll();
      toast('导入完成,已按修改时间合并 ✅');
    } catch (e) { toast('导入失败:' + e.message, 'err'); }
  };
  fr.readAsText(file);
}

/* ============ 11. 初始化向导 / 恢复 ============ */
const WZ = { step: 1, token: null };
function wzShow(step) {
  WZ.step = step;
  $$('#m-wizard .wz-step').forEach(s => s.hidden = +s.dataset.step !== step);
  $$('#wz-dots i').forEach((d, i) => d.classList.toggle('on', i < step));
  $('#btn-wz-prev').hidden = step === 1;
  $('#btn-wz-next').textContent = step === 4 ? '完成初始化' : '下一步';
}
async function wzNext() {
  const err3 = $('#wz-err3'), err2 = $('#wz-err2'), err4 = $('#wz-err4');
  err2.hidden = err3.hidden = err4.hidden = true;
  if (WZ.step === 1) { wzShow(2); return; }
  if (WZ.step === 2) {
    const name = $('#wz-user').value.trim(), p1 = $('#wz-pass').value, p2 = $('#wz-pass2').value;
    if (!/^[a-zA-Z0-9_-]{2,20}$/.test(name)) { err2.textContent = '用户名需 2-20 位,仅限字母/数字/_/-'; err2.hidden = false; return; }
    if (p1.length < 8) { err2.textContent = '密码至少 8 位'; err2.hidden = false; return; }
    if (p1 !== p2) { err2.textContent = '两次输入的密码不一致'; err2.hidden = false; return; }
    WZ.user = name; WZ.pass = p1;
    wzShow(3); return;
  }
  if (WZ.step === 3) {
    if (!WZ.token) { err3.textContent = '请先点击「验证令牌」'; err3.hidden = false; return; }
    $('#wz-done-text').textContent = '一切就绪!点击按钮完成初始化(将创建账号表并进入日记)。';
    wzShow(4); return;
  }
  if (WZ.step === 4) {
    const btn = $('#btn-wz-next');
    btn.disabled = true; btn.textContent = '初始化中…';
    try {
      const acc = await readAccounts();
      if (acc.users && Object.keys(acc.users).length) throw new Error('检测到已有账号,请直接登录,或使用「忘记密码」恢复');
      const { enc, ctx } = await sealToken(WZ.pass, WZ.token);
      await putContents(CFG.SITE_REPO, 'accounts.json',
        { version: 1, users: { [WZ.user]: { role: 'admin', createdAt: Date.now(), enc } } },
        acc.sha, WZ.token, 'chore: 初始化账号表');
      const fresh = freshData(WZ.user);
      const r2 = await putContents(CFG.DATA_REPO, `data/${WZ.user}.json`, fresh, null, WZ.token, 'diary: 初始化数据');
      S.user = WZ.user; S.role = 'admin'; S.token = WZ.token; S.encCtx = ctx;
      localStorage.setItem('kyd_creds', JSON.stringify({ user: S.user, role: 'admin', token: WZ.token }));
      closeModal('m-wizard');
      await enterApp();
      toast('初始化完成,开始记录你的研途吧 🎉');
    } catch (e) {
      err4.textContent = '初始化失败:' + e.message; err4.hidden = false;
      btn.disabled = false; btn.textContent = '完成初始化';
    }
  }
}
async function wzValidate() {
  const status = $('#wz-tk-status'), err = $('#wz-err3');
  const token = $('#wz-token').value.trim();
  err.hidden = true;
  if (!token) { status.textContent = '请先粘贴令牌'; status.className = 'tk-status err'; return; }
  status.textContent = '验证中…'; status.className = 'tk-status';
  const v = await validateToken(token);
  if (v.ok) {
    WZ.token = token;
    status.textContent = '✓ 验证通过,两个仓库均可访问';
    status.className = 'tk-status ok';
  } else {
    WZ.token = null;
    status.textContent = '✗ ' + v.msg;
    status.className = 'tk-status err';
  }
}
function pwMeter() {
  const p = $('#wz-pass').value;
  let score = 0;
  if (p.length >= 8) score++;
  if (p.length >= 12) score++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++;
  if (/\d/.test(p)) score++;
  if (/[^a-zA-Z0-9]/.test(p)) score++;
  const lv = p.length === 0 ? 0 : p.length < 8 ? 1 : score >= 4 ? 3 : score >= 2 ? 2 : 1;
  const meter = $('.pw-meter');
  meter.dataset.lv = lv;
  $('#wz-pw-text').textContent = ['', '弱', '中', '强'][lv];
}

/* ============ 12. 通用 UI(弹窗/确认/Toast/主题) ============ */
function openModal(id) { $('#' + id).hidden = false; }
function closeModal(id) { $('#' + id).hidden = true; }
let confirmResolve = null;
function confirmBox({ title = '确认', text = '', input = null, okText = '确定' }) {
  return new Promise(res => {
    confirmResolve = res;
    $('#confirm-title').textContent = title;
    $('#confirm-text').textContent = text;
    const box = $('#confirm-input-box'), inp = $('#confirm-input');
    if (input) {
      box.hidden = false;
      $('#confirm-input-label').textContent = input.label || '';
      inp.type = input.type || 'text';
      inp.value = input.value || '';
      setTimeout(() => inp.focus(), 50);
    } else box.hidden = true;
    $('#btn-confirm-ok').textContent = okText;
    openModal('m-confirm');
  });
}
function settleConfirm(val) { closeModal('m-confirm'); if (confirmResolve) { confirmResolve(val); confirmResolve = null; } }
function toast(msg, type = '') {
  const root = $('#toast-root');
  while (root.children.length >= 3) root.firstChild.remove();
  const t = el('div', 'toast ' + type, msg);
  root.append(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 320); }, 2600);
}
function initTheme() {
  let t = localStorage.getItem('kyd_theme');
  if (!t) t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
}
function toggleTheme() {
  const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = t;
  localStorage.setItem('kyd_theme', t);
}

/* ============ 13. 事件绑定 ============ */
function bindEvents() {
  /* 登录 */
  $('#form-login').addEventListener('submit', async e => {
    e.preventDefault();
    const err = $('#li-err'); err.hidden = true;
    const btn = $('#btn-login');
    btn.disabled = true; btn.textContent = '登录中…';
    try {
      await doLogin($('#li-user').value.trim(), $('#li-pass').value, $('#li-remember').checked);
    } catch (e2) {
      err.textContent = e2.message; err.hidden = false;
      btn.disabled = false; btn.textContent = '登 录';
    }
  });
  $('#lnk-demo').addEventListener('click', enterDemo);
  $('#lnk-wizard').addEventListener('click', () => { wzShow(1); openModal('m-wizard'); });
  $('#lnk-recover').addEventListener('click', () => openModal('m-recover'));
  /* 向导 */
  $('#btn-wz-next').addEventListener('click', wzNext);
  $('#btn-wz-prev').addEventListener('click', () => wzShow(Math.max(1, WZ.step - 1)));
  $('#btn-wz-validate').addEventListener('click', wzValidate);
  $('#wz-token').addEventListener('input', () => { WZ.token = null; $('#wz-tk-status').textContent = ''; });
  $('#wz-pass').addEventListener('input', pwMeter);
  /* 恢复 */
  $('#btn-recover').addEventListener('click', async () => {
    const err = $('#rc-err'); err.hidden = true;
    const name = $('#rc-user').value.trim(), p1 = $('#rc-pass').value, p2 = $('#rc-pass2').value, token = $('#rc-token').value.trim();
    const fail = m => { err.textContent = m; err.hidden = false; };
    if (!name || p1.length < 8 || p1 !== p2) return fail('请填写账号与一致的 8 位以上新密码');
    if (!token) return fail('请粘贴有效的 GitHub 令牌');
    try { await doRecover(name, p1, token); closeModal('m-recover'); }
    catch (e) { fail(e.message); }
  });
  /* 顶栏 */
  $('#btn-theme').addEventListener('click', toggleTheme);
  $('#user-menu-btn').addEventListener('click', e => { e.stopPropagation(); $('#user-menu').hidden = !$('#user-menu').hidden; });
  document.addEventListener('click', e => {
    if (!$('#user-menu').hidden && !e.target.closest('.user-box')) $('#user-menu').hidden = true;
  });
  $('#user-menu').addEventListener('click', e => {
    const act = e.target.closest('.menu-item')?.dataset.act;
    if (!act) return;
    $('#user-menu').hidden = true;
    if (act === 'settings') openSettings('account');
    if (act === 'admin') { if (S.role === 'admin') openSettings('users'); }
    if (act === 'password') { openSettings('account'); setTimeout(() => $('#pw-old').focus(), 100); }
    if (act === 'export') exportData();
    if (act === 'logout') logout();
  });
  $('#sync-state').addEventListener('click', () => { if ($('#sync-text').textContent.includes('失败')) syncNow(); });
  /* 日期导航 */
  $('#btn-prev-day').addEventListener('click', () => selectDate(addDaysKey(S.selDate, -1)));
  $('#btn-next-day').addEventListener('click', () => selectDate(addDaysKey(S.selDate, 1)));
  $('#btn-today').addEventListener('click', () => selectDate(todayKey()));
  $('#date-input').addEventListener('change', e => { if (e.target.value) selectDate(e.target.value); });
  /* 心情 / 标签 / 日记 */
  $('#mood-row').addEventListener('click', e => {
    const b = e.target.closest('.mood-btn'); if (!b) return;
    const d = dayOf(S.selDate);
    d.mood = d.mood === b.dataset.mood ? '' : b.dataset.mood;
    d.updatedAt = Date.now();
    $$('#mood-row .mood-btn').forEach(x => x.classList.toggle('on', x.dataset.mood === d.mood));
    markDirty();
  });
  $('#tag-row').addEventListener('click', e => {
    const b = e.target.closest('.tag-chip'); if (!b) return;
    const d = dayOf(S.selDate);
    const i = d.tags.indexOf(b.dataset.tag);
    if (i >= 0) d.tags.splice(i, 1); else d.tags.push(b.dataset.tag);
    b.classList.toggle('on', i < 0);
    d.updatedAt = Date.now();
    markDirty();
  });
  $('#diary-text').addEventListener('input', onDiaryInput);
  $('#diary-text').addEventListener('keydown', e => e.stopPropagation());
  window.addEventListener('resize', debounce(autoGrow, 200));
  /* 打卡 */
  $('#subject-rows').addEventListener('click', e => {
    const q = e.target.closest('.qbtn');
    if (q) {
      addMinutes(q.dataset.sub, parseInt(q.dataset.d, 10));
      return;
    }
    const n = e.target.closest('.mins-num');
    if (n && !n.querySelector('input')) editMins(n.dataset.sub, n);
  });
  $('#timer-subjects').addEventListener('click', e => {
    const c = e.target.closest('.tsub'); if (!c) return;
    S.timerSub = c.dataset.s;
    localStorage.setItem('kyd_tsub', S.timerSub);
    if (!T || !T.running) renderTimer();
  });
  $('#btn-timer-main').addEventListener('click', toggleTimer);
  $('#btn-timer-stop').addEventListener('click', stopTimer);
  $('#btn-timer-discard').addEventListener('click', discardTimer);
  /* 往期 */
  $('#arch-search').addEventListener('input', debounce(() => { archShown = 60; renderArchive(); }, 200));
  $('#arch-more').addEventListener('click', () => { archShown += 60; renderArchive(); });
  /* 热力图 */
  const hm = $('#heatmap');
  hm.addEventListener('mouseover', e => { const c = e.target.closest('.hm-cell'); if (c && c.dataset.k) heatTip(c.dataset.k, c); });
  hm.addEventListener('mouseout', e => { if (e.target.closest('.hm-cell')) $('#tooltip').hidden = true; });
  hm.addEventListener('click', e => {
    const c = e.target.closest('.hm-cell'); if (!c || !c.dataset.k) return;
    selectDate(c.dataset.k);
    $('#card-diary').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  /* 设置 */
  $('#set-nav').addEventListener('click', e => { const t = e.target.closest('.set-tab'); if (t) switchTab(t.dataset.tab); });
  $('#btn-save-prefs').addEventListener('click', savePrefs);
  $('#btn-changepw').addEventListener('click', changePassword);
  $('#btn-au-create').addEventListener('click', adminCreateUserReal);
  $('#btn-export').addEventListener('click', exportData);
  $('#import-file').addEventListener('change', e => { if (e.target.files[0]) importData(e.target.files[0]); e.target.value = ''; });
  $('#btn-token-save').addEventListener('click', replaceToken);
  /* 确认框 */
  $('#btn-confirm-ok').addEventListener('click', () => {
    const box = $('#confirm-input');
    settleConfirm(!box.hidden ? box.value : true);
  });
  $('#btn-confirm-cancel').addEventListener('click', () => settleConfirm(null));
  $('#confirm-input').addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Enter') settleConfirm($('#confirm-input').value);
    if (e.key === 'Escape') settleConfirm(null);
  });
  /* 弹窗关闭 */
  $$('.modal-overlay').forEach(ov => {
    ov.addEventListener('click', e => {
      if (e.target === ov) {
        if (ov.id === 'm-confirm') settleConfirm(null);
        else ov.hidden = true;
      }
    });
    ov.querySelectorAll('[data-close]').forEach(x => x.addEventListener('click', () => {
      if (ov.id === 'm-confirm') settleConfirm(null); else ov.hidden = true;
    }));
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      const open = $$('.modal-overlay').find(m => !m.hidden);
      if (open) { if (open.id === 'm-confirm') settleConfirm(null); else open.hidden = true; }
      else if (!$('#user-menu').hidden) $('#user-menu').hidden = true;
    }
  });
  /* 网络与生命周期 */
  window.addEventListener('online', () => { if (S.dirty) syncNow(); else setSync('ok'); });
  window.addEventListener('offline', () => setSync('offline'));
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') flushOnHide(); });
  window.addEventListener('pagehide', flushOnHide);
  /* 跨零点刷新 */
  setInterval(() => {
    const tk = todayKey();
    if (tk !== S.today && S.view === 'app') {
      S.today = tk; S.selDate = tk;
      renderAll();
    }
    if (T && T.running) renderTimer();
  }, 30000);
}
function selectDate(k) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(k)) return;
  S.selDate = k;
  renderDiary(); renderTimeCard();
}

/* ============ 启动 ============ */
boot();
