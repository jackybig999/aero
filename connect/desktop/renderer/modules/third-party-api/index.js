import { thirdPartyApi } from '../../api/bridge.js'
let _reg=null,_providers=[],_sid='deepseek',_models=[],_testOk=false,_testMsg='',_noModels=false,_timer=0,_shimPorts={}

const META={deepseek:{n:'DeepSeek',kp:'sk-',urls:{'标准':{u:'https://api.deepseek.com',f:'openai'},'Claude兼容':{u:'https://api.deepseek.com/anthropic',f:'claude'}},tk:{cl:'direct',cx:'shim'}},
  openai:{n:'OpenAI',kp:'sk-',urls:{'标准':{u:'https://api.openai.com/v1',f:'openai'}},tk:{cl:'shim',cx:'direct'}},
  anthropic:{n:'Anthropic Claude',kp:'sk-ant-',urls:{'标准':{u:'https://api.anthropic.com/v1',f:'claude'}},tk:{cl:'direct',cx:'shim'}},
  gemini:{n:'Google Gemini',kp:'AIza',urls:{'标准':{u:'https://generativelanguage.googleapis.com/v1beta',f:'gemini'}},tk:{cl:'shim',cx:'shim'}},
  groq:{n:'Groq',kp:'gsk_',urls:{'标准':{u:'https://api.groq.com/openai/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  together:{n:'Together AI',kp:'',urls:{'标准':{u:'https://api.together.xyz/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  mistral:{n:'Mistral AI',kp:'',urls:{'标准':{u:'https://api.mistral.ai/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  xai:{n:'xAI Grok',kp:'xai-',urls:{'标准':{u:'https://api.x.ai/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  moonshot:{n:'Kimi (月之暗面)',kp:'sk-',urls:{'标准':{u:'https://api.moonshot.cn/v1',f:'openai'},'CodingPlan':{u:'https://api.moonshot.cn/coding',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  glm:{n:'智谱 GLM',kp:'',urls:{'标准':{u:'https://open.bigmodel.cn/api/paas/v4',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  minimax:{n:'MiniMax',kp:'',urls:{'标准':{u:'https://api.minimax.chat/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  baichuan:{n:'百川 Baichuan',kp:'',urls:{'标准':{u:'https://api.baichuan-ai.com/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  qwen:{n:'通义千问 Qwen',kp:'sk-',urls:{'标准':{u:'https://dashscope.aliyuncs.com/compatible-mode/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}},
  silicon:{n:'硅基流动 SiliconFlow',kp:'sk-',urls:{'标准':{u:'https://api.siliconflow.cn/v1',f:'openai'}},tk:{cl:'direct',cx:'shim'}}}
const TL={cl:'Claude CLI',cx:'Codex CLI'}

function T(k,f){return(_reg&&_reg.i18n)?(_reg.i18n.t(k)||f):f}
function E(id){return document.getElementById(id)}
function ce(t,c){const e=document.createElement(t);if(c)e.className=c;return e}
function CM(){return META[_sid]}
function CP(){return _providers.find(p=>p.id===_sid)}
function curUrls(){const m=CM();return m?.urls||{}}
function curUrl(){const cp=CP();return cp?.custUrl||E('tpapi-url')?.value||Object.values(curUrls())[0]?.u||''}
function curFmt(){const u=E('tpapi-url')?.value||'';if(u.includes('/anthropic')||u.includes('/claude'))return'claude';if(u.includes('generativelanguage')||u.includes('/gemini'))return'gemini';return Object.values(curUrls())[0]?.f||'openai'}

// ─── build ─────────────────────────────────────────────────────────────────────
function buildOverlay(){const mk=ce('div','tpapi-mask');mk.id='tpapi-mask';const pn=ce('div','tpapi-panel');pn.appendChild(hdr(pn));const bd=ce('div','tpapi-body')
  const r1=ce('div','tpapi-row');const l1=ce('label','');l1.textContent='Provider:';const sl=ce('select','');sl.id='tpapi-sel';sl.style.flex='1';sl.onchange=()=>{_sid=sl.value;_testOk=false;_testMsg='';_models=[];_noModels=false;refreshUI()};r1.appendChild(l1);r1.appendChild(sl)
  const dbtn=ce('button','btn-text');dbtn.id='tpapi-cust-del';dbtn.textContent='✕';dbtn.title=T('tpDelete','删除');dbtn.style.display='none';dbtn.style.color='var(--error)'
  dbtn.onclick=async()=>{if(!confirm(T('tpConfirmDel','确认删除此自定义Provider？')))return;await thirdPartyApi.del({id:_sid});await loadData();_sid=_providers[0]?.id||'deepseek';refreshUI()};r1.appendChild(dbtn)
  const cbtn=ce('button','btn-text');cbtn.textContent='+ '+T('tpCustom','自定义');cbtn.onclick=()=>toggleCustom();r1.appendChild(cbtn);bd.appendChild(r1)
  const cf=ce('div','tpapi-custom');cf.id='tpapi-custom';cf.style.display='none';cf.innerHTML=`<input id="tpapi-cname" placeholder="${T('tpCustName','名称')}" style="width:45%"><input id="tpapi-curl" placeholder="${T('tpCustUrl','Base URL')}" style="width:45%"><button class="btn-text" id="tpapi-csave">✓ ${T('tpSave','保存')}</button>`;bd.appendChild(cf)
  const r2=ce('div','tpapi-row');const l2=ce('label','');l2.textContent='🌐 Base URL';const ui=ce('input','');ui.id='tpapi-url';ui.style.cssText='font-size:11px;font-family:monospace';ui.readOnly=true;const eb=ce('button','btn-text');eb.textContent='✎';eb.onclick=()=>{ui.readOnly=!ui.readOnly;eb.textContent=ui.readOnly?'✎':'✓';if(!ui.readOnly)ui.focus()};ui.oninput=()=>{updateFmt();filterTools()};r2.appendChild(l2);r2.appendChild(ui);r2.appendChild(eb);bd.appendChild(r2)
  const tags=ce('div','tpapi-tags');tags.id='tpapi-tags';bd.appendChild(tags)
  const fl=ce('div','tpapi-fmt');fl.id='tpapi-fmt';bd.appendChild(fl)
  const r3=ce('div','tpapi-row');const l3=ce('label','');l3.textContent='🔑 API Key';const ky=ce('input','');ky.id='tpapi-key';ky.type='password';ky.placeholder='sk-... / gsk_... / AIza...';ky.oninput=()=>{autoDetect(ky.value);debounceTest()};const ey=ce('button','btn-text');ey.textContent='👁';ey.onclick=()=>{ky.type=ky.type==='password'?'text':'password'};r3.appendChild(l3);r3.appendChild(ky);r3.appendChild(ey);bd.appendChild(r3)
  const ht=ce('div','tpapi-hint');ht.id='tpapi-hint';bd.appendChild(ht)
  const tr=ce('div','tpapi-test-result');tr.id='tpapi-test-result';bd.appendChild(tr)
  const r4=ce('div','tpapi-row');const l4=ce('label','');l4.textContent='🤖 '+T('tpModel','模型选择');const ms=ce('select','');ms.id='tpapi-model-sel';ms.style.cssText='flex:1;background:var(--bg-primary);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);padding:6px 8px;font-size:12px';ms.onchange=()=>{const cp=CP();if(cp)cp.model=ms.value};r4.appendChild(l4);r4.appendChild(ms);bd.appendChild(r4)
  const r5=ce('div','');r5.style.cssText='font-size:12px;color:var(--text-secondary);margin-top:8px';r5.textContent='📋 '+T('tpConfigTools','配置工具')+':';bd.appendChild(r5)
  const tc=ce('div','tpapi-tools');tc.id='tpapi-tools';for(const[tid,tn]of Object.entries(TL)){const lb=ce('label','tpapi-tool-item');const cb=ce('input','');cb.type='checkbox';cb.id='tptool-'+tid;cb.checked=true;lb.appendChild(cb);lb.appendChild(document.createTextNode(' '+tn));const sp=ce('span','');sp.id='tptool-'+tid+'-info';sp.style.cssText='margin-left:8px;font-size:11px;color:var(--text-secondary)';lb.appendChild(sp);tc.appendChild(lb)};bd.appendChild(tc)
  const ac=ce('div','tpapi-actions');ac.style.cssText='display:flex;align-items:center;gap:8px'
  const st=ce('span','');st.id='tpapi-cfg-status';st.style.cssText='flex:1;font-size:12px;color:var(--text-secondary)';ac.appendChild(st)
  for(const[a,lb,cn]of[['apply',T('tpApply','应用配置'),'btn-primary'],['restore',T('tpRestore','恢复默认'),'btn-secondary']]){const bn=ce('button',cn);bn.textContent=lb;bn.style.cssText='padding:6px 14px;font-size:12px';bn.onclick=()=>doAction(a);ac.appendChild(bn)};bd.appendChild(ac)
  pn.appendChild(bd);mk.appendChild(pn);return mk}
function hdr(pn){const h=ce('div','tpapi-header');h.style.cursor='move';h.onmousedown=e=>{if(e.target.tagName==='BUTTON')return;pn.style.position='fixed';pn.style.margin='0';const r=pn.getBoundingClientRect();const ox=e.clientX-r.left;const oy=e.clientY-r.top;const mv=ev=>{pn.style.left=Math.max(0,ev.clientX-ox)+'px';pn.style.top=Math.max(0,ev.clientY-oy)+'px'};const up=()=>{document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up)};document.addEventListener('mousemove',mv);document.addEventListener('mouseup',up)};const t=ce('h3','');t.textContent=T('tpApiTitle','第三方API');const c=ce('button','btn-icon');c.textContent='✕';c.onclick=closeOverlay;h.appendChild(t);h.appendChild(c);return h}

// ─── tags + format ─────────────────────────────────────────────────────────────
function renderTags(){const el=E('tpapi-tags');if(!el)return;el.textContent='';const us=curUrls();const cp=CP();const curTag=cp?.urlTag||Object.keys(us)[0]||'';const keys=Object.keys(us);if(keys.length<=1)return;for(const k of keys){const cfg=us[k];const tag=ce('button','tpapi-tag');tag.textContent=k;if(k===curTag)tag.classList.add('active');tag.onclick=()=>{if(cp)cp.urlTag=k;E('tpapi-url').value=cfg.u||'';_testOk=false;_testMsg='';_models=[];_noModels=false;E('tpapi-test-result').textContent='';updateFmt();filterTools();renderTags();renderModels();updateToolInfo();debounceTest()};el.appendChild(tag)}}
function updateFmt(){const fl=E('tpapi-fmt');if(!fl)return;const f=curFmt();const lb={openai:'📋 OpenAI 兼容格式',claude:'📋 Claude 原生格式',gemini:'📋 Gemini 格式'};fl.textContent=lb[f]||'📋 '+f.toUpperCase()}

// ─── custom + detect + test ────────────────────────────────────────────────────
function toggleCustom(){const cf=E('tpapi-custom');if(!cf)return;const vis=cf.style.display==='none';cf.style.display=vis?'flex':'none';if(vis){E('tpapi-csave').onclick=async()=>{const n=E('tpapi-cname')?.value?.trim();if(!n)return alert(T('tpNeedName','请输入名称'));const u=E('tpapi-curl')?.value?.trim();if(!u)return alert(T('tpNeedUrl','请输入 Base URL'));const id='cust_'+Date.now();await thirdPartyApi.save({id,apiKey:'',model:'',baseUrl:u,custName:n,custFmt:'openai'});await loadData();_sid=id;refreshUI();cf.style.display='none';E('tpapi-cname').value='';E('tpapi-curl').value=''}}}
function autoDetect(v){const ht=E('tpapi-hint');if(!ht)return;if(!v){ht.textContent='';return};const cm=CM();if(cm?.kp&&v.startsWith(cm.kp)){ht.textContent='💡 '+cm.n+' API';return};for(const p of _providers){const m=META[p.id];if(!m?.kp||!v.startsWith(m.kp))continue;ht.textContent=`💡 ${T('tpAutoDetect','检测到')}: ${m.n} API`;return};ht.textContent=''}
function debounceTest(){clearTimeout(_timer);_timer=setTimeout(()=>doTest(false),800)}
async function doTest(silent){const kv=E('tpapi-key')?.value?.trim();if(!kv)return;const bu=curUrl();if(!bu)return;const cp=CP();if(!cp)return;await thirdPartyApi.save({id:_sid,apiKey:kv,model:cp.model||'',baseUrl:bu,urlTag:cp.urlTag||''});const r=await thirdPartyApi.test({id:_sid,baseUrl:bu,fmt:curFmt()});_testOk=r.success;_noModels=!!r.noModels;_testMsg=r.success?`✅ ${T('tpTestOk','连接成功')} (${r.latency}ms, ${(r.models||[]).length}个模型)`:r.noModels?`✅ ${T('tpTestOk','连接成功')} (Claude格式无模型列表)`:`❌ ${T('tpTestFail','连接失败')}: ${r.error||'未知错误'}`;_models=r.models||[];renderModels();E('tpapi-test-result').textContent=_testMsg;E('tpapi-test-result').style.color=r.success?'var(--success)':'var(--error)';updateToolInfo();if(!silent)log(_testMsg)}

// ─── models (100% API real-time) ──────────────────────────────────────────────
function renderModels(){const sel=E('tpapi-model-sel');const st=E('tpapi-models-status');if(!sel)return;sel.textContent='';if(st)st.textContent='';const cp=CP()
  if(!_testOk){sel.disabled=true;const o=ce('option','');o.textContent=T('tpNoModels','输入 Key 后自动获取');sel.appendChild(o);return}
  if(_models.length===0){sel.disabled=true;const o=ce('option','');o.textContent=_noModels?T('tpNoModels2','Claude格式不支持模型列表'):'⚠️ API 未返回模型列表';sel.appendChild(o);return}
  sel.disabled=false;const selM=cp?.model||_models[0]||''
  for(const name of _models){const o=ce('option','');o.value=name;o.textContent=name;if(name===selM)o.selected=true;sel.appendChild(o)}
  if(st)st.textContent=`${_models.length} 个模型`;if(st)st.style.cssText='font-size:10px;color:var(--text-secondary);padding:2px 0'}
function filterTools(){const f=curFmt();const showCl=f==='claude';const showCx=f==='openai'||f==='gemini';for(const[tid]of Object.entries(TL)){const row=E('tptool-'+tid)?.parentElement;if(row){if((tid==='cl'&&!showCl)||(tid==='cx'&&!showCx))row.style.display='none';else row.style.display=''}}}
function updateToolInfo(){const m=CM();for(const[tid]of Object.entries(TL)){const info=E('tptool-'+tid+'-info');if(!info)continue;const need=m?(m.tk[tid]==='shim'):false;const cb=E('tptool-'+tid);if(_shimPorts[tid]){info.textContent='● '+T('tpShimRunning','转换中')+' (127.0.0.1:'+_shimPorts[tid]+')';info.style.color='var(--accent)';if(cb)cb.disabled=false}else if(need&&_testOk){info.textContent='⚠️ '+T('tpNeedShim','需转换（应用时自动启动）');info.style.color='var(--warning)';if(cb)cb.disabled=false}else if(need){info.textContent='⚠️ '+T('tpNeedShim','需协议转换');info.style.color='var(--warning)';if(cb)cb.disabled=false}else if(_testOk){info.textContent='✅ '+T('tpDirectConfig','直接配置调用');info.style.color='var(--success)'}else{info.textContent='⏳ '+T('tpNeedTest','待测试');info.style.color='var(--text-secondary)'}}}

// ─── refresh + actions ─────────────────────────────────────────────────────────
function refreshUI(){const sl=E('tpapi-sel');if(!sl)return;sl.textContent='';for(const p of _providers){const o=ce('option','');o.value=p.id;o.textContent=p.custName||p.name;if(p.id===_sid)o.selected=true;sl.appendChild(o)};const cp=CP();const us=curUrls();const defTag=cp?.urlTag||Object.keys(us)[0]||'';const uc=us[defTag]||Object.values(us)[0]||{};const ue=E('tpapi-url');if(ue)ue.value=cp?.custUrl||uc.u||'';const delBtn=E('tpapi-cust-del');if(delBtn)delBtn.style.display=cp?.isC?'':'none';renderTags();updateFmt();E('tpapi-key').value=cp?.apiKey||'';_testOk=false;_testMsg='';_models=[];_noModels=false;E('tpapi-test-result').textContent='';filterTools();renderModels();updateToolInfo()}
async function doAction(act){const kv=E('tpapi-key')?.value?.trim()||'';const bu=curUrl();const cp=CP();if(!cp)return;const defM=cp.model||_models[0]||'';const mdl=cp.model||defM;if((act==='test'||act==='apply')&&!kv)return alert(T('tpNeedKey','请先输入 API Key'));if(act==='test'){await doTest(true);return};if(act==='apply'){const sel=[];for(const tid of Object.keys(TL)){if(E('tptool-'+tid)?.checked)sel.push(tid)};if(!sel.length)return alert(T('tpSelectTool','请至少勾选一个工具'));if(!_testOk){await doTest(true);if(!_testOk)return alert(_testMsg)};await thirdPartyApi.save({id:_sid,apiKey:kv,model:mdl,baseUrl:bu,urlTag:cp.urlTag||''});const r=await thirdPartyApi.apply({id:_sid,tools:sel,baseUrl:bu});if(r.success){const msgs=[];for(const x of r.results){const st=x.shim?'🔄 '+T('tpShimStarted','已启动转换'):T('tpConfigured','已配置');msgs.push(`${x.action==='ok'?'✅':x.action==='skipped'?'⚠️':'❌'} ${x.name}: ${x.action==='ok'?st:x.reason||x.error}`)};if(r.shim){for(const[tid,inf]of Object.entries(r.shim))_shimPorts[tid]=inf.port};let stMsg='';for(const x of r.results){if(x.action==='ok'){stMsg+=(x.shim?'🔄 Codex CLI 转换端口 127.0.0.1:'+x.port+' ':'✅ Claude CLI 配置完成 ')}};if(E('tpapi-cfg-status'))E('tpapi-cfg-status').textContent=stMsg||'';log(T('tpApplyResult','配置结果')+':\n'+msgs.join('\n'));await loadData();refreshUI()};return};if(act==='restore'){const r=await thirdPartyApi.restore({id:_sid});_shimPorts={};if(E('tpapi-cfg-status'))E('tpapi-cfg-status').textContent='';refreshUI();log(r.success&&r.restored?.length?`🔄 ${T('tpRestored','配置已恢复，原始文件已还原')}: ${r.restored.map(x=>x.name).join(', ')}`:T('tpNoBackup','没有可恢复的备份文件'))}}
function log(msg){_reg?.bus?.emit('log:append',`[${new Date().toLocaleTimeString()}] ${msg}`)}

function closeOverlay(){E('tpapi-mask')?.remove();document.removeEventListener('keydown',onKey)}
function onKey(e){if(e.key==='Escape')closeOverlay()}
async function loadData(){const r=await thirdPartyApi.list();if(r.success)_providers=r.providers}
async function showOverlay(){E('tpapi-mask')?.remove();await loadData();if(!_providers.find(p=>p.id===_sid))_sid=_providers[0]?.id||'deepseek';_testOk=false;_testMsg='';_models=[];_noModels=false;const ov=buildOverlay();document.body.appendChild(ov);refreshUI();ov.onclick=e=>{if(e.target===ov)closeOverlay()};document.addEventListener('keydown',onKey)}
function updateBtn(){const btn=E('btn-third-party');if(btn)btn.textContent=T('tpApiTitle','第三方API')}
export const thirdPartyApiModule={name:'third-party-api',init(reg){_reg=reg;updateBtn();const btn=E('btn-third-party');if(btn)btn.onclick=showOverlay},async refresh(){updateBtn();if(E('tpapi-mask')){await showOverlay()}},destroy(){document.removeEventListener('keydown',onKey);E('tpapi-mask')?.remove()}}
