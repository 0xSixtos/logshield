import { redact, TYPES, MAX_BYTES } from './detector.js';

const $ = id => document.getElementById(id);
const words = {
  es: {
    workspace:'ESPACIO DE TRABAJO', editor:'Editor de logs', demo:'Probar ejemplo', how:'CÓMO FUNCIONA',
    step1:'Abre o pega tu archivo',step2:'Revisa las detecciones',step3:'Comparte una copia',
    localTitle:'Tus archivos se quedan aquí.',localBody:'Sin subidas. Sin cuentas. Sin almacenamiento en el navegador.',tool:'HERRAMIENTAS /',browserLocal:'Procesamiento local',
    headline:'Comparte el log.<br><span>No tus secretos.</span>',subtitle:'Detecta credenciales y datos sensibles antes de compartir. <br>Revisa cada cambio. Conserva el control.',
    reviewSpace:'Revisión de archivo',original:'Original',openFile:'Abrir archivo',clear:'Limpiar',sourceLabel:'Texto original para revisar',maxSize:'Máx. 2 MB · UTF-8',cleanCopy:'Copia censurada',preview:'VISTA PREVIA',replacementKey:'Reemplazos visibles',detect:'Detectar',secrets:'Secretos',emails:'Correos',ips:'Direcciones IP',scan:'Analizar texto',findingsTitle:'Tú decides qué ocultar',selectAll:'Seleccionar todo',exportTitle:'Lista para compartir.',exportBody:'Una copia nueva. El archivo original permanece intacto.',download:'Descargar copia',copy:'Copiar texto',report:'Descargar resumen sin secretos',limitation:'La detección por patrones puede omitir secretos o marcar texto válido. Revisa la copia antes de compartirla.',madeFor:'HECHO PARA COMPARTIR MEJOR',
    placeholder:'Pega aquí tu texto o arrastra un archivo…',emptyPreview:'Tu copia censurada aparecerá aquí.\n\nAnaliza el texto para revisar los posibles secretos.',emptyFindings:'Analiza un archivo para revisar las detecciones.',cleanFindings:'No se detectaron coincidencias con los patrones activos. Revisa el contenido antes de compartirlo.',scanning:'Analizando localmente…',ready:'Ejemplo ficticio cargado. Ningún dato pertenece a una cuenta real.',edited:'El texto cambió. Vuelve a analizarlo para actualizar la copia.',cleared:'Contenido eliminado de esta página.',copied:'Copia censurada en el portapapeles.',copyError:'No se pudo acceder al portapapeles. Descarga la copia.',downloaded:'Copia censurada descargada.',tooLarge:'El límite es de 2 MB. Divide el archivo y vuelve a intentarlo.',binary:'Selecciona un archivo de texto UTF-8, no un archivo binario.',error:'No se pudo analizar el archivo. Prueba con un texto más pequeño.',deep:'El JSON tiene demasiados niveles. Simplifica el archivo antes de analizarlo.',workerError:'No se pudo iniciar el análisis local. Abre la app desde un servidor HTTP.',truncated:'Se alcanzó el límite de detecciones. Divide el archivo: la exportación está bloqueada para evitar una copia incompleta.',invalidJson:'El texto parece JSON, pero no es válido. Se analizará y descargará como texto.',sampleFile:'ejemplo.json',pasted:'texto pegado',line:'Línea',column:'col.',found:'detecciones',hidden:'ocultas',visible:'visibles por tu decisión',lines:'líneas',noHidden:'Sin reemplazos seleccionados',noGuarantee:'Sin coincidencias. Esto no garantiza que no existan secretos.',reviewReady:'Revisión preparada. Puedes ajustar cada detección antes de exportar.',ignored:'Hay detecciones que has decidido dejar visibles.',type_PASSWORD:'Contraseña',type_API_KEY:'Clave API',type_TOKEN:'Token de sesión',type_AUTH:'Autorización',type_COOKIE:'Cookie',type_PRIVATE_KEY:'Clave privada',type_CREDENTIALS:'Credenciales en URL',type_EMAIL:'Correo electrónico',type_IP_ADDRESS:'Dirección IP',reviewCheck:'Ocultar',fileReady:'Archivo abierto. Pulsa Analizar texto.',selectCategory:'Activa al menos un tipo de detección.',
  },
  en: {
    workspace:'WORKSPACE',editor:'Log editor',demo:'Try an example',how:'HOW IT WORKS',step1:'Open or paste your file',step2:'Review every detection',step3:'Share a clean copy',localTitle:'Your files stay right here.',localBody:'No uploads. No accounts. No browser storage.',tool:'TOOLS /',browserLocal:'Processed on your device',headline:'Share the log.<br><span>Not your secrets.</span>',subtitle:'Find credentials and sensitive data before you share. <br>Review every change. Stay in control.',reviewSpace:'File review',original:'Original',openFile:'Open file',clear:'Clear',sourceLabel:'Original text to review',maxSize:'Max. 2 MB · UTF-8',cleanCopy:'Redacted copy',preview:'PREVIEW',replacementKey:'Visible replacements',detect:'Detect',secrets:'Secrets',emails:'Emails',ips:'IP addresses',scan:'Analyze text',findingsTitle:'You decide what stays private',selectAll:'Select all',exportTitle:'Ready to share.',exportBody:'A separate copy. Your original file stays untouched.',download:'Download copy',copy:'Copy text',report:'Download secret-free summary',limitation:'Pattern detection can miss secrets or flag harmless text. Review the copy before sharing.',madeFor:'BUILT FOR BETTER SHARING',placeholder:'Paste your text or drop a file here…',emptyPreview:'Your redacted copy will appear here.\n\nAnalyze text to review potential secrets.',emptyFindings:'Analyze a file to review detections.',cleanFindings:'No active patterns matched. Review the content before sharing.',scanning:'Analyzing locally…',ready:'Fictional example loaded. None of this data belongs to a real account.',edited:'Text changed. Analyze again to update the copy.',cleared:'Content cleared from this page.',copied:'Redacted text copied to clipboard.',copyError:'Clipboard is unavailable. Download the copy instead.',downloaded:'Redacted copy downloaded.',tooLarge:'The limit is 2 MB. Split the file and try again.',binary:'Choose a UTF-8 text file, not a binary file.',error:'Could not analyze this file. Try a smaller input.',deep:'This JSON is too deeply nested. Simplify the file first.',workerError:'Local analysis could not start. Serve the app over HTTP.',truncated:'Detection limit reached. Split the file: export is blocked to avoid an incomplete copy.',invalidJson:'This looks like JSON, but is invalid. It will be analyzed and exported as text.',sampleFile:'example.json',pasted:'pasted text',line:'Line',column:'col.',found:'detections',hidden:'hidden',visible:'left visible by you',lines:'lines',noHidden:'No replacements selected',noGuarantee:'No matches. This does not guarantee there are no secrets.',reviewReady:'Review ready. Adjust each detection before exporting.',ignored:'Some detections have been left visible by you.',type_PASSWORD:'Password',type_API_KEY:'API key',type_TOKEN:'Session token',type_AUTH:'Authorization',type_COOKIE:'Cookie',type_PRIVATE_KEY:'Private key',type_CREDENTIALS:'URL credentials',type_EMAIL:'Email address',type_IP_ADDRESS:'IP address',reviewCheck:'Redact',fileReady:'File opened. Select Analyze text.',selectCategory:'Enable at least one detection type.',
  },
};
const sample = JSON.stringify({timestamp:'2026-10-25T12:00:00Z',level:'info',service:'demo-checkout',request:{method:'POST',path:'/api/orders',authorization:'Bearer fictional_token_for_demo_only',api_key:'sk-proj-FAKEEXAMPLE0000000000000000',session_id:'session-example-only'},user:{email:'alex@example.com',password:'not-a-real-password'},database:{url:'https://demo:fictional-password@db.example.com:443/demo'},debug:{contact:'support@example.org',latency_ms:148}},null,2);
let language = 'es';
let result = null;
let original = '';
let selected = new Set();
let requestId = 0;
let fileName = '';
let isDemo = true;
let worker;
let statusKey = 'ready';
let toastTimer;
const t = key => words[language][key] ?? key;

function status(key, kind = '') { statusKey = key; $('status').textContent = t(key); $('status').className = `status ${kind}`; }
function toast(key) { $('toast').textContent = t(key); $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3500); }
function updateMeta() {
  const bytes = new TextEncoder().encode($('source').value).length;
  $('source-meta').textContent = `${$('source').value ? $('source').value.split('\n').length : 0} ${t('lines')} · ${bytes < 1000 ? `${bytes} B` : `${(bytes / 1000).toFixed(1)} KB`}`;
  $('file-label').textContent = isDemo ? t('sampleFile') : fileName || t('pasted');
}
function invalidate() {
  requestId++;
  result = null;
  selected.clear();
  $('scan').disabled = false;
  render();
  updateMeta();
}
function render() {
  const output = $('output'); output.replaceChildren();
  const list = $('findings'); const previousScroll = list.scrollTop; list.replaceChildren();
  if (!result) {
    output.textContent = t('emptyPreview'); output.className = 'output-empty';
    const empty = document.createElement('div'); empty.className = 'empty-findings'; empty.textContent = t('emptyFindings'); list.append(empty);
    $('findings-count').textContent = '0'; $('output-meta').textContent = '—'; $('export-summary').textContent = '';
    for (const id of ['download','copy','report','select-all']) $(id).disabled = true;
    return;
  }
  output.className = '';
  let cursor = 0;
  for (const finding of result.findings) {
    if (!selected.has(finding.id)) continue;
    output.append(document.createTextNode(original.slice(cursor, finding.start)));
    const mark = document.createElement('mark'); mark.textContent = finding.replacement; mark.title = `${t('type_'+finding.type)} · ${t('line')} ${finding.line}`; output.append(mark);
    cursor = finding.end;
  }
  output.append(document.createTextNode(original.slice(cursor)));
  const hidden = selected.size;
  const visible = result.findings.length - hidden;
  $('findings-count').textContent = result.findings.length;
  $('output-meta').textContent = `${result.format.toUpperCase()} · ${hidden} ${t('hidden')}`;
  $('export-summary').textContent = visible ? `${hidden} ${t('hidden')} · ${visible} ${t('visible')}` : `${hidden} ${t('hidden')} · ${result.format.toUpperCase()}`;
  $('export-summary').className = `export-summary ${visible ? 'warn' : ''}`;
  for (const f of result.findings) {
    const label = document.createElement('label'); label.className = `finding${selected.has(f.id) ? '' : ' unselected'}`;
    const check = document.createElement('input'); check.type = 'checkbox'; check.id = `finding-${f.id}`; check.checked = selected.has(f.id); check.setAttribute('aria-label',`${t('reviewCheck')} ${t('type_'+f.type)}, ${t('line')} ${f.line}, ${t('column')} ${f.column}`);
    check.addEventListener('change', () => { check.checked ? selected.add(f.id) : selected.delete(f.id); render(); document.getElementById(check.id)?.focus({preventScroll:true}); status(result.truncated ? 'truncated' : selected.size < result.findings.length ? 'ignored' : 'reviewReady', result.truncated || selected.size < result.findings.length ? 'warning' : ''); });
    const icon = document.createElement('span'); icon.className='finding-icon'; icon.textContent = f.type === 'EMAIL' ? '@' : f.type === 'IP_ADDRESS' ? '#' : '⌑'; icon.setAttribute('aria-hidden','true');
    const text = document.createElement('span'); text.className='finding-text';
    const type = document.createElement('span'); type.className='finding-type'; type.textContent=t('type_'+f.type);
    const location = document.createElement('span'); location.className='finding-location'; location.textContent=`${t('line')} ${f.line} · ${t('column')} ${f.column}`;
    text.append(type,location);
    const placeholder = document.createElement('span'); placeholder.className='finding-placeholder'; placeholder.textContent=f.replacement;
    label.append(check,icon,text,placeholder); list.append(label);
  }
  if (!result.findings.length) { const empty=document.createElement('div'); empty.className='empty-findings'; empty.textContent=t('cleanFindings'); list.append(empty); }
  list.scrollTop = previousScroll;
  for (const id of ['download','copy','report']) $(id).disabled = result.truncated;
  $('select-all').disabled = !result.findings.length;
}
function analyze() {
  if (!worker) { status('workerError','error'); return; }
  if (!$('source').value.trim()) { invalidate(); status('cleared'); return; }
  if (new TextEncoder().encode($('source').value).length > MAX_BYTES) { invalidate(); status('tooLarge','error'); return; }
  if (!$('detect-secrets').checked && !$('detect-emails').checked && !$('detect-ips').checked) { invalidate(); status('selectCategory','warning'); return; }
  result = null; render(); original = $('source').value;
  const id = ++requestId;
  const options = Object.fromEntries(TYPES.map(type => [type,type === 'EMAIL' ? $('detect-emails').checked : type === 'IP_ADDRESS' ? $('detect-ips').checked : $('detect-secrets').checked]));
  status('scanning'); $('scan').disabled = true;
  worker.postMessage({ id, text:original, options });
}
function outputText() {
  if (!result || result.truncated || original !== $('source').value) throw Error('No current review');
  const output = redact(original,result.findings,selected);
  if (result.format === 'json') JSON.parse(output); // Never export broken JSON.
  return output;
}
function save(body,name,mime) {
  const url = URL.createObjectURL(new Blob([body],{type:mime}));
  const a=document.createElement('a'); a.href=url; a.download=name; document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function loadFile(file) {
  if (!file) return;
  if (file.size > MAX_BYTES) { status('tooLarge','error'); return; }
  try {
    const buffer = await file.arrayBuffer();
    const text = new TextDecoder('utf-8',{fatal:true}).decode(buffer);
    if (text.includes('\0')) throw Error('binary');
    $('source').value=text; fileName=file.name; isDemo=false; invalidate(); status('fileReady');
  } catch { status('binary','error'); }
  $('file-input').value='';
}
function loadDemo() { $('source').value=sample; isDemo=true; fileName=''; invalidate(); analyze(); }
function changeLanguage() {
  language=language==='es'?'en':'es'; document.documentElement.lang=language;
  for (const node of document.querySelectorAll('[data-i18n]')) {
    const value=t(node.dataset.i18n);
    // Only this fixed, developer-authored heading contains HTML. User input uses text nodes.
    if (node.dataset.i18n==='headline') node.innerHTML=value;
    else if (node.dataset.i18n==='subtitle') node.innerHTML=value;
    else node.textContent=value;
  }
  $('source').placeholder=t('placeholder'); $('clear').title=t('clear'); $('clear').setAttribute('aria-label',t('clear'));
  $('lang-button').textContent=language==='es'?'EN ↗':'ES ↗'; $('lang-button').setAttribute('aria-label',language==='es'?'Switch to English':'Cambiar a español');
  $('output').setAttribute('aria-label',language==='es'?'Vista previa de la copia censurada':'Redacted copy preview');
  updateMeta(); render(); status(statusKey,$('status').classList.contains('error')?'error':$('status').classList.contains('warning')?'warning':'');
}

try {
  worker = new Worker('./worker.js',{type:'module'});
  worker.onmessage=({data})=>{
    if(data.id!==requestId) return;
    $('scan').disabled=false;
    if(data.error) { result=null; render(); status(data.error==='FILE_TOO_LARGE'?'tooLarge':data.error==='JSON_TOO_DEEP'?'deep':'error','error'); return; }
    result=data.result; selected=new Set(result.findings.map(f=>f.id)); render();
    status(result.truncated?'truncated':result.invalidJson?'invalidJson':isDemo?'ready':result.findings.length?'reviewReady':'noGuarantee',result.truncated||result.invalidJson?'warning':'');
  };
  worker.onerror=()=>{ worker.terminate();worker=null; result=null;render();$('scan').disabled=false;status('workerError','error'); };
} catch { status('workerError','error'); }
$('source').addEventListener('input',()=>{isDemo=false;invalidate();status('edited');});
$('scan').addEventListener('click',analyze);
for(const id of ['sample-top','sample-side']) $(id).addEventListener('click',loadDemo);
$('lang-button').addEventListener('click',changeLanguage);
$('clear').addEventListener('click',()=>{$('source').value='';fileName='';isDemo=false;original='';invalidate();status('cleared');$('source').focus();});
$('open-file').addEventListener('click',()=>$('file-input').click());
$('file-input').addEventListener('change',event=>loadFile(event.target.files[0]));
$('dropzone').addEventListener('dragover',event=>{event.preventDefault();$('dropzone').classList.add('drag-over');});
$('dropzone').addEventListener('dragleave',()=>$('dropzone').classList.remove('drag-over'));
$('dropzone').addEventListener('drop',event=>{event.preventDefault();$('dropzone').classList.remove('drag-over');loadFile(event.dataTransfer.files[0]);});
for(const id of ['detect-secrets','detect-emails','detect-ips']) $(id).addEventListener('change',()=>{if($('source').value.trim()) analyze();});
$('select-all').addEventListener('click',()=>{if(!result)return;selected=new Set(result.findings.map(f=>f.id));render();status(result.truncated?'truncated':'reviewReady',result.truncated?'warning':'');});
$('download').addEventListener('click',()=>{try{const clean=outputText();const base=(fileName||'logshield').replace(/\.[^.]+$/,'').replace(/[^a-zA-Z0-9_-]/g,'_').slice(0,80)||'logshield';save(clean,`${base}.redacted.${result.format==='json'?'json':'txt'}`,result.format==='json'?'application/json':'text/plain;charset=utf-8');toast('downloaded');}catch{status('error','error');}});
$('copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(outputText());toast('copied');}catch{toast('copyError');}});
$('report').addEventListener('click',()=>{if(!result||result.truncated)return;const summary={tool:'LogShield',version:'0.1.0',format:result.format,detected:result.findings.length,redacted:selected.size,limitations:'Pattern matching may miss secrets or flag harmless text. Review output manually.',findings:result.findings.map(f=>({type:f.type,line:f.line,column:f.column,redacted:selected.has(f.id)}))};save(JSON.stringify(summary,null,2),'logshield.review.json','application/json');});
document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key==='Enter'){event.preventDefault();analyze();}});
loadDemo();
