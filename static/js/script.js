const historyItems = []
let currentMode = 'url'
let selectedFile = null
let screenshotPollTimer = null
let urlscanPollTimer = null
let screenshotPollUuid = null
const SCREENSHOT_POLL_MS = 5000
const SCREENSHOT_POLL_MAX_MS = 4 * 60 * 1000
const URLSCAN_POLL_MS = 5000
const URLSCAN_POLL_MAX_ATTEMPTS = 60

function clearPollTimers() {
  if (screenshotPollTimer) { clearInterval(screenshotPollTimer); screenshotPollTimer = null }
  if (urlscanPollTimer) { clearInterval(urlscanPollTimer); urlscanPollTimer = null }
  screenshotPollUuid = null
}

// Frontend result cache: url -> data
const _frontCache = {}
const FRONT_CACHE_TTL = 300000 // 5 min in ms
const API_BASE = location.protocol === 'file:' ? 'http://127.0.0.1:5000' : ''

function apiUrl(path) {
  return API_BASE + path
}

function screenshotPollUrl(us) {
  if (!us || !us.available) return null
  if (us.screenshot_proxy) return apiUrl(us.screenshot_proxy)
  if (us.uuid) return apiUrl(`/urlscan-screenshot/${encodeURIComponent(us.uuid)}`)
  return us.screenshot_url || null
}

async function readJson(res) {
  const text = await res.text()
  try {
    return JSON.parse(text)
  } catch (err) {
    throw new Error(`Server returned HTTP ${res.status}${text ? ': ' + text.slice(0, 120) : ''}`)
  }
}

function switchMode(mode) {
  currentMode = mode
  document.getElementById('tabUrl').classList.toggle('active', mode === 'url')
  document.getElementById('tabFile').classList.toggle('active', mode === 'file')
  document.getElementById('urlMode').style.display = mode === 'url' ? 'block' : 'none'
  document.getElementById('fileMode').style.display = mode === 'file' ? 'block' : 'none'
  document.getElementById('fileZone').classList.toggle('active-mode', mode === 'file')
}

// Drag and drop
function onDragOver(e) { e.preventDefault(); document.getElementById('fileZone').classList.add('drag-over'); }
function onDragLeave(e) { document.getElementById('fileZone').classList.remove('drag-over'); }
function onDrop(e) {
  e.preventDefault()
  document.getElementById('fileZone').classList.remove('drag-over')
  const f = e.dataTransfer.files[0]
  if (f) setFile(f)
}
function onFileSelect(e) {
  const f = e.target.files[0]
  if (f) setFile(f)
}
function setFile(f) {
  selectedFile = f
  document.getElementById('fileSelectedName').textContent = f.name
  document.getElementById('fileSelected').classList.add('show')
  document.getElementById('fileAnalyzeBtn').classList.add('show')
}
function clearFile() {
  selectedFile = null
  document.getElementById('fileInput').value = ''
  document.getElementById('fileSelected').classList.remove('show')
  document.getElementById('fileAnalyzeBtn').classList.remove('show')
}

function toggleSidebar() {
  const open = document.getElementById('sidebar').classList.toggle('open')
  document.getElementById('overlay').classList.toggle('show', open)
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open')
  document.getElementById('overlay').classList.remove('show')
}

function initCanvas() {
  const canvas = document.getElementById('bgCanvas')
  const ctx = canvas.getContext('2d')
  let W, H, circles
  function resize() {
    W = canvas.width = window.innerWidth
    H = canvas.height = window.innerHeight
    circles = Array.from({length: 6}, () => ({
      x: Math.random()*W, y: Math.random()*H,
      r: 180+Math.random()*220,
      dx: (Math.random()-0.5)*0.18, dy: (Math.random()-0.5)*0.18,
      hue: [200,220,240,260,30,160][Math.floor(Math.random()*6)],
      alpha: 0.04+Math.random()*0.05
    }))
  }
  function draw() {
    ctx.clearRect(0,0,W,H)
    ctx.fillStyle = '#f5f4f0'; ctx.fillRect(0,0,W,H)
    circles.forEach(c => {
      const g = ctx.createRadialGradient(c.x,c.y,0,c.x,c.y,c.r)
      g.addColorStop(0,`hsla(${c.hue},60%,70%,${c.alpha})`)
      g.addColorStop(1,`hsla(${c.hue},60%,70%,0)`)
      ctx.beginPath(); ctx.arc(c.x,c.y,c.r,0,Math.PI*2)
      ctx.fillStyle=g; ctx.fill()
      c.x+=c.dx; c.y+=c.dy
      if(c.x<-c.r)c.x=W+c.r; if(c.x>W+c.r)c.x=-c.r
      if(c.y<-c.r)c.y=H+c.r; if(c.y>H+c.r)c.y=-c.r
    })
    requestAnimationFrame(draw)
  }
  resize(); window.addEventListener('resize',resize); draw()
}
initCanvas()

function resetUI() {
  clearPollTimers()
  document.getElementById('hero').classList.remove('has-results')
  document.getElementById('results').style.display = 'none'
  document.getElementById('urlInput').value = ''
  document.getElementById('chain').innerHTML = ''
  ;['summaryCard','aiCard','pageCard','intelRow','screenshotCard','metaCard'].forEach(id =>
    document.getElementById(id).classList.remove('show'))
  document.getElementById('chainHeader').classList.remove('show')
  document.getElementById('statusRow').classList.remove('show')
  document.getElementById('progressSteps').classList.remove('show')
  document.querySelectorAll('.progress-step').forEach(el => {
    el.classList.remove('is-active', 'is-done', 'is-skip')
  })
  document.getElementById('errorBox').classList.remove('show')
  document.getElementById('errorBox').textContent = ''
  document.getElementById('urlResults').style.display = 'block'
  document.getElementById('fileResults').style.display = 'none'
  document.querySelectorAll('.history-item').forEach(i => i.classList.remove('active'))
}

function showProgress() {
  document.getElementById('progressSteps').classList.add('show')
  document.querySelectorAll('.progress-step').forEach(el => {
    el.classList.remove('is-active', 'is-done', 'is-skip')
  })
}

function setProgressStep(step, state) {
  const el = document.querySelector(`.progress-step[data-step="${step}"]`)
  if (!el) return
  el.classList.remove('is-active', 'is-done', 'is-skip')
  if (state) el.classList.add(state)
}

function hideProgressWhenDone() {
  const steps = document.querySelectorAll('.progress-step')
  const allDone = [...steps].every(el =>
    el.classList.contains('is-done') || el.classList.contains('is-skip'))
  if (allDone) {
    setTimeout(() => document.getElementById('progressSteps').classList.remove('show'), 600)
  }
}

function renderUrlResults(data, fromCache) {
  renderSummary(data.overall_risk, data.chain || [], data.elapsed, fromCache)
  renderChain(data.chain)
  renderPageAnalysis(data.page_analysis || {})
  renderIntel(data.virustotal || {}, data.urlscan || {})
  renderScreenshot(data.urlscan || {})
  pollUrlscan(data.urlscan || {})
  renderAI(data.ai_analysis || {})
}

function finishUrlAnalyze() {
  document.getElementById('analyzeBtn').disabled = false
  hideProgressWhenDone()
}

function showError(msg) {
  const e = document.getElementById('errorBox')
  e.textContent = msg; e.classList.add('show')
}

function levelInfo(score) {
  if (score === 0) return {level:'clean',  text:'No suspicious signals found in this chain.'}
  if (score < 25)  return {level:'low',    text:'One or more minor signals. Look closer before opening.'}
  if (score < 55)  return {level:'medium', text:'Multiple suspicious signals. Proceed with caution.'}
  return                  {level:'high',   text:'Serious red flags across the chain. Do not open.'}
}

// ---------- URL analysis ----------

async function analyze() {
  const url = document.getElementById('urlInput').value.trim()
  if (!url) return

  clearPollTimers()
  document.getElementById('hero').classList.add('has-results')
  document.getElementById('results').style.display = 'block'
  document.getElementById('urlResults').style.display = 'block'
  document.getElementById('fileResults').style.display = 'none'
  document.getElementById('chain').innerHTML = ''
  ;['summaryCard','aiCard','pageCard','intelRow','screenshotCard','metaCard'].forEach(id =>
    document.getElementById(id).classList.remove('show'))
  document.getElementById('chainHeader').classList.remove('show')
  document.getElementById('errorBox').classList.remove('show')
  document.getElementById('errorBox').textContent = ''
  document.getElementById('analyzeBtn').disabled = true

  const cacheKey = url.toLowerCase().trim()
  const cached = _frontCache[cacheKey]
  if (cached && (Date.now() - cached.ts) < FRONT_CACHE_TTL) {
    addHistory(url, cached.data.overall_risk)
    renderUrlResults(cached.data, true)
    finishUrlAnalyze()
    return
  }

  showProgress()
  setProgressStep('chain', 'is-active')

  const bar = document.getElementById('barFill')
  bar.style.transition = 'none'
  bar.style.width = '0%'
  setTimeout(() => { bar.style.transition = '' }, 50)

  const postJson = (path, body) =>
    fetch(apiUrl(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

  try {
    const chainRes = await postJson('/analyze/chain', { url })
    let chainData = await readJson(chainRes)
    if (chainData.error) {
      showError(chainData.error)
      finishUrlAnalyze()
      return
    }

    if (chainData.cached) {
      const fullRes = await postJson('/analyze', { url })
      chainData = await readJson(fullRes)
      if (chainData.error) {
        showError(chainData.error)
        finishUrlAnalyze()
        return
      }
      _frontCache[cacheKey] = { ts: Date.now(), data: chainData }
      addHistory(url, chainData.overall_risk)
      renderUrlResults(chainData, true)
      finishUrlAnalyze()
      return
    }

    addHistory(url, chainData.overall_risk)
    renderSummary(chainData.overall_risk, chainData.chain || [], chainData.elapsed, false)
    renderChain(chainData.chain)
    renderPageAnalysis(chainData.page_analysis || {})
    setProgressStep('chain', 'is-done')
    setProgressStep('page', 'is-done')

    setProgressStep('intel', 'is-active')
    setProgressStep('ai', 'is-active')

    const intelPromise = postJson('/analyze/intel', { url }).then(r => readJson(r))
    const aiPromise = postJson('/analyze/ai', {
      url,
      chain: chainData.chain,
      html_excerpt: chainData.html_excerpt || '',
    }).then(r => readJson(r))

    intelPromise.then(intelData => {
      if (intelData.error) {
        showError(intelData.error)
        setProgressStep('intel', 'is-skip')
        setProgressStep('screenshot', 'is-skip')
        return
      }
      renderIntel(intelData.virustotal || {}, intelData.urlscan || {})
      setProgressStep('intel', 'is-done')
      const us = intelData.urlscan || {}
      if (us.available && us.uuid) {
        setProgressStep('screenshot', 'is-active')
        renderScreenshot(us)
        if (!us.ready) pollUrlscan(us)
      } else if (us.error) {
        renderScreenshot(us)
        setProgressStep('screenshot', 'is-skip')
      } else {
        setProgressStep('screenshot', 'is-skip')
      }
    }).catch(() => {
      setProgressStep('intel', 'is-skip')
      setProgressStep('screenshot', 'is-skip')
    })

    aiPromise.then(aiData => {
      if (aiData.error) {
        setProgressStep('ai', 'is-skip')
        return
      }
      renderAI(aiData.ai_analysis || {})
      setProgressStep('ai', 'is-done')
    }).catch(() => setProgressStep('ai', 'is-skip'))

    const [intelData, aiData] = await Promise.all([intelPromise, aiPromise])
    const merged = {
      ...chainData,
      virustotal: intelData.virustotal,
      urlscan: intelData.urlscan,
      ai_analysis: aiData.ai_analysis,
      cached: false,
    }
    _frontCache[cacheKey] = { ts: Date.now(), data: merged }
    finishUrlAnalyze()

  } catch (err) {
    finishUrlAnalyze()
    showError(err.message || 'Could not reach the server. Is the Flask app running on port 5000?')
  }
}

// ---------- File analysis ----------

async function analyzeFile() {
  if (!selectedFile) return

  document.getElementById('hero').classList.add('has-results')
  document.getElementById('results').style.display = 'block'
  document.getElementById('urlResults').style.display = 'none'
  document.getElementById('fileResults').style.display = 'block'
  document.getElementById('metaCard').classList.remove('show')
  document.getElementById('errorBox').classList.remove('show')
  document.getElementById('errorBox').textContent = ''
  document.getElementById('statusRow').classList.add('show')
  document.getElementById('statusText').textContent = 'Scanning file metadata...'
  document.getElementById('fileAnalyzeBtn').disabled = true

  try {
    const formData = new FormData()
    formData.append('file', selectedFile)
    formData.append('external_intel', 'false')

    const res = await fetch(apiUrl('/analyze-file'), { method: 'POST', body: formData })
    const data = await readJson(res)

    document.getElementById('statusRow').classList.remove('show')
    document.getElementById('fileAnalyzeBtn').disabled = false

    if (data.error) { showError(data.error); return }
    if (!data.available) { showError(data.error || 'Metadata extraction unavailable'); return }

    addHistoryFile(selectedFile.name, data.risk_score || 0)
    renderMetadata(data)

  } catch(err) {
    document.getElementById('statusRow').classList.remove('show')
    document.getElementById('fileAnalyzeBtn').disabled = false
    showError(err.message || 'Could not reach the server. Is the Flask app running on port 5000?')
  }
}

// ---------- Render: URL results ----------

function renderSummary(score, chain, elapsed, fromCache) {
  const {level, text} = levelInfo(score)
  const chip = document.getElementById('riskChip')
  chip.textContent = level + ' risk'
  chip.className = 'risk-chip chip-' + level
  document.getElementById('barFill').className = 'bar-fill fill-' + level
  document.getElementById('summaryText').textContent = text

  const flagCount  = (chain||[]).reduce((n,h) => n + (h.flags||[]).length, 0)
  const hopCount   = (chain||[]).length
  const redirCount = (chain||[]).filter(h => h.status_code && [301,302,303,307,308].includes(h.status_code)).length
  const detailEl   = document.getElementById('summaryDetail')
  if (detailEl) {
    const parts = []
    parts.push(`${hopCount} hop${hopCount !== 1 ? 's' : ''}`)
    if (redirCount) parts.push(`${redirCount} redirect${redirCount !== 1 ? 's' : ''}`)
    parts.push(`${flagCount} signal${flagCount !== 1 ? 's' : ''} flagged`)
    if (elapsed) parts.push(`${elapsed}s`)
    if (fromCache) parts.push('cached')
    detailEl.textContent = parts.join('  Â·  ')
  }

  document.getElementById('summaryCard').classList.add('show')
  setTimeout(() => { document.getElementById('barFill').style.width = Math.max(score,4)+'%' }, 60)
}

function bustUrl(url) {
  return url + (url.includes('?') ? '&' : '?') + 't=' + Date.now()
}

function stopScreenshotPoll() {
  if (screenshotPollTimer) {
    clearInterval(screenshotPollTimer)
    screenshotPollTimer = null
  }
}

function renderScreenshot(us) {
  if (!us || !us.available || !us.uuid) return

  const card = document.getElementById('screenshotCard')
  const img = document.getElementById('screenshotImg')
  const loading = document.getElementById('screenshotLoading')
  const reportLink = document.getElementById('screenshotReportLink')
  const src = screenshotPollUrl(us)

  if (us.error) {
    card.classList.add('show')
    loading.style.display = 'flex'
    loading.textContent = 'urlscan: ' + us.error
    setProgressStep('screenshot', 'is-skip')
    return
  }
  if (!src) return

  stopScreenshotPoll()
  screenshotPollUuid = us.uuid

  card.classList.add('show')
  if (us.report_url) reportLink.href = us.report_url

  const showImage = () => {
    loading.style.display = 'none'
    img.style.display = 'block'
    setProgressStep('screenshot', 'is-done')
    hideProgressWhenDone()
  }

  const showWaiting = (msg) => {
    img.style.display = 'none'
    loading.style.display = 'flex'
    loading.innerHTML = msg || '<div class="spinner"></div> Loading sandbox screenshot...'
    setProgressStep('screenshot', 'is-active')
  }

  showWaiting()

  img.onload = showImage
  img.onerror = () => showWaiting('<div class="spinner"></div> Loading sandbox screenshot...')
  img.src = bustUrl(src)

  if (us.ready) return

  const started = Date.now()
  const attempt = () => {
    if (Date.now() - started >= SCREENSHOT_POLL_MAX_MS) {
      stopScreenshotPoll()
      const href = reportLink.href && reportLink.href !== '#' ? reportLink.href : ''
      loading.innerHTML = href
        ? 'Screenshot not ready yet. <a class="screenshot-link" href="' + href + '" target="_blank">Open urlscan report</a>'
        : 'Screenshot not ready yet.'
      setProgressStep('screenshot', 'is-skip')
      hideProgressWhenDone()
      return
    }
    const probe = new Image()
    probe.onload = () => {
      stopScreenshotPoll()
      img.src = probe.src
      showImage()
    }
    probe.onerror = () => {}
    probe.src = bustUrl(src)
  }

  attempt()
  screenshotPollTimer = setInterval(attempt, SCREENSHOT_POLL_MS)
}

function renderAI(ai) {
  if (!ai.available || !ai.purpose) return
  const colors = {benign:'var(--clean)', suspicious:'var(--medium)', likely_malicious:'var(--high)'}
  const threat = document.getElementById('aiThreat')
  threat.textContent = (ai.threat_assessment||'').replace('_',' ')
  threat.style.color = colors[ai.threat_assessment] || 'var(--text-2)'
  document.getElementById('aiPurpose').textContent = ai.purpose || ''
  document.getElementById('aiTags').innerHTML = (ai.tags||[]).map(t=>`<span class="ai-tag">${t}</span>`).join('')
  const meta = document.getElementById('aiMeta')
  meta.innerHTML = ''
  if ((ai.vibe_score ?? -1) >= 0) {
    meta.innerHTML += `<div class="ai-meta-item">AI-generated vibe
      <div class="vibe-wrap">
        <div class="vibe-track"><div class="vibe-fill" id="vibeBar"></div></div>
        <span>${ai.vibe_score}</span>
      </div>
    </div>`
  }
  if (ai.ai_content_detected !== undefined) {
    meta.innerHTML += `<div class="ai-meta-item">AI-written text: ${ai.ai_content_detected ? 'detected' : 'not detected'}</div>`
  }
  if (ai.vibe_reason) {
    meta.innerHTML += `<div class="ai-meta-item" style="width:100%">Vibe: ${ai.vibe_reason}</div>`
  }
  // Advice + threat reason
  const adviceParts = []
  if (ai.threat_reason) adviceParts.push(ai.threat_reason)
  if (ai.journalist_advice) adviceParts.push(ai.journalist_advice)
  document.getElementById('aiAdvice').textContent = adviceParts.join(' ')
  document.getElementById('aiCard').classList.add('show')
  setTimeout(() => {
    const vb = document.getElementById('vibeBar')
    if (vb) vb.style.width = (ai.vibe_score||0)+'%'
  }, 100)
}

function renderIntel(vt, us) {
  let show = false
  if (vt.available) {
    show = true
    const mal = vt.malicious||0, sus = vt.suspicious||0
    const el = document.getElementById('vtVal')
    el.textContent = mal
    el.style.color = mal>0 ? 'var(--high)' : sus>0 ? 'var(--medium)' : 'var(--clean)'
    document.getElementById('vtSub').textContent = `${mal} malicious, ${sus} suspicious, ${vt.harmless||0} clean`
  }
  if (us.available) {
    show = true
    document.getElementById('urlscanVal').textContent = us.ready ? 'Report ready' : 'Pending'
    const verdicts = us.verdicts || {}
    const overall = verdicts.overall || {}
    let sub = us.ready ? 'Report ready' : 'Waiting for urlscan report...'
    if (us.ready) {
      if (overall.malicious) sub = 'Flagged malicious'
      else if (overall.score > 0) sub = `Score: ${overall.score}`
      if ((overall.categories||[]).length) sub += ' · ' + overall.categories.slice(0,2).join(', ')
    }
    document.getElementById('urlscanSub').textContent = sub
    if (us.report_url) {
      const link = document.getElementById('urlscanLink')
      link.href = us.report_url; link.style.display = 'inline-flex'
    }
  }
  if (show) document.getElementById('intelRow').classList.add('show')
}

function pollUrlscan(us) {
  if (!us.available || !us.uuid) return
  if (us.ready) {
    renderIntel({}, us)
    stopScreenshotPoll()
    screenshotPollUuid = null
    renderScreenshot(us)
    return
  }
  if (urlscanPollTimer) return

  if (us.report_url) {
    const link = document.getElementById('urlscanLink')
    link.href = us.report_url
    link.style.display = 'inline-flex'
  }

  let attempts = 0
  urlscanPollTimer = setInterval(async () => {
    attempts++
    try {
      const res = await fetch(apiUrl(`/urlscan-result/${encodeURIComponent(us.uuid)}?t=${Date.now()}`))
      const updated = await readJson(res)
      if (updated.report_url) {
        const link = document.getElementById('urlscanLink')
        link.href = updated.report_url
        link.style.display = 'inline-flex'
        document.getElementById('screenshotReportLink').href = updated.report_url
      }
      if (updated.ready) {
        clearInterval(urlscanPollTimer)
        urlscanPollTimer = null
        renderIntel({}, updated)
        stopScreenshotPoll()
        screenshotPollUuid = null
        renderScreenshot(updated)
        return
      }
    } catch (err) {}
    if (attempts >= URLSCAN_POLL_MAX_ATTEMPTS) {
      clearInterval(urlscanPollTimer)
      urlscanPollTimer = null
      document.getElementById('urlscanVal').textContent = 'Pending'
      document.getElementById('urlscanSub').textContent = 'Open the full report to view results'
    }
  }, URLSCAN_POLL_MS)
}

function renderPageAnalysis(pa) {
  if (!pa || (!pa.trackers?.length && !pa.fingerprints?.length && !pa.miners?.length && !pa.script_domains?.length)) {
    return
  }
  const groups = document.getElementById('pageGroups')
  groups.innerHTML = ''
  const addGroup = (label, items, cls) => {
    if (!items?.length) return
    const d = document.createElement('div')
    d.innerHTML = `<div class="page-group-label">${label}</div>
      <div class="tag-list">${items.map(i=>`<span class="page-tag ${cls}">${i}</span>`).join('')}</div>`
    groups.appendChild(d)
  }
  if (pa.miners?.length)       addGroup('Crypto miners', pa.miners, 'miner')
  if (pa.fingerprints?.length) addGroup('Fingerprinting scripts', pa.fingerprints, 'fingerprint')
  if (pa.trackers?.length)     addGroup('Trackers', pa.trackers, 'tracker')
  if (pa.script_domains?.length) addGroup('External scripts', pa.script_domains, 'script')

  if (!pa.miners?.length && !pa.fingerprints?.length && !pa.trackers?.length) {
    groups.innerHTML = '<div class="page-clean"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>No trackers or fingerprinters detected</div>'
  }
  document.getElementById('pageCard').classList.add('show')
}

function renderChain(hops) {
  const container = document.getElementById('chain')
  document.getElementById('chainHeader').classList.add('show')
  hops.forEach(hop => {
    const level = hop.risk_level || 'unknown'
    const row = document.createElement('div'); row.className = 'hop-row'
    const tl  = document.createElement('div'); tl.className = 'hop-timeline'
    const dot = document.createElement('div'); dot.className = `hop-dot dot-${level}`
    const line= document.createElement('div'); line.className = 'hop-line'
    tl.appendChild(dot); tl.appendChild(line)
    const card  = document.createElement('div'); card.className = 'hop-card'
    const top   = document.createElement('div'); top.className = 'hop-top'
    const urlEl = document.createElement('div'); urlEl.className = 'hop-url'
    urlEl.textContent = hop.url || 'unknown'
    top.appendChild(urlEl)
    if (hop.trusted) {
      const t = document.createElement('div'); t.className = 'hop-trusted'
      t.innerHTML = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>trusted`
      top.appendChild(t)
    } else {
      const badge = document.createElement('div')
      badge.className = `level-badge badge-${level}`
      badge.textContent = level
      top.appendChild(badge)
    }
    const pills = document.createElement('div'); pills.className = 'hop-pills'
    const pillData = []
    if (hop.ip && hop.ip !== 'unknown' && hop.ip !== 'unresolvable') pillData.push(hop.ip)
    if (hop.asn?.country && hop.asn.country !== '??') pillData.push(hop.asn.country)
    if (hop.asn?.org && hop.asn.org !== 'unknown' && hop.asn.org !== 'private') pillData.push(hop.asn.org.slice(0,22))
    if (hop.tls?.issuer && hop.tls.issuer !== 'unknown' && hop.tls.issuer !== 'http only') pillData.push('TLS: '+hop.tls.issuer.slice(0,18))
    if (hop.tls?.age_days > 0) pillData.push('cert '+hop.tls.age_days+'d old')
    if (hop.tls?.expires_in_days >= 0 && hop.tls.expires_in_days < 30) pillData.push('expires in '+hop.tls.expires_in_days+'d')
    if (hop.domain_age?.age_days > 0) pillData.push(hop.domain_age.age_days+'d old')
    if (hop.domain_age?.registrar && hop.domain_age.registrar !== 'unknown') pillData.push(hop.domain_age.registrar.slice(0,20))
    // Security headers
    const hdrs = hop.headers || {}
    if (!hdrs['content-security-policy']) pillData.push('no CSP')
    if (!hdrs['x-frame-options'] && !hdrs['content-security-policy']) pillData.push('no X-Frame-Options')
    if (hdrs['server'] && hdrs['server'].length < 40) pillData.push('srv: '+hdrs['server'].slice(0,20))
    if (hdrs['x-powered-by']) pillData.push('powered-by: '+hdrs['x-powered-by'].slice(0,20))
    pillData.forEach(p => {
      const s = document.createElement('span'); s.className='pill'; s.textContent=p; pills.appendChild(s)
    })
    const flags = document.createElement('div'); flags.className = 'hop-flags'
    ;(hop.flags||[]).forEach(f => {
      const s = document.createElement('span')
      // critical flags get a darker red
      const isCrit = /homoglyph|punycode|download|ZIP|self-signed|redirect loop/i.test(f)
      s.className = isCrit ? 'flag flag-crit' : 'flag'
      s.textContent = f
      flags.appendChild(s)
    })
    const http = document.createElement('div'); http.className = 'hop-http'
    if (hop.status_code) http.textContent = 'HTTP '+hop.status_code
    if (hop.error)       http.textContent = hop.error
    card.appendChild(top)
    if (pillData.length)        card.appendChild(pills)
    if ((hop.flags||[]).length) card.appendChild(flags)
    card.appendChild(http)
    row.appendChild(tl); row.appendChild(card)
    container.appendChild(row)
  })
}

// ---------- Render: File metadata ----------

const LEVEL_COLORS = {clean:'var(--clean)', low:'var(--low)', medium:'var(--medium)', high:'var(--high)'}
const CAT_LABELS = {
  gps: 'ðŸ“ GPS & Location',
  author: 'ðŸ‘¤ Author & Identity',
  device: 'ðŸ“· Device & Equipment',
  timestamps: 'ðŸ• Timestamps',
  location_text: 'ðŸŒ Location Text',
  identity: 'ðŸªª Document Identity',
  network: 'ðŸ”Œ Network & System',
}
const CAT_DANGER = new Set(['gps','author','location_text'])

function renderMetadata(data) {
  const card = document.getElementById('metaCard')
  const score = data.risk_score || 0
  const level = score === 0 ? 'clean' : score < 25 ? 'low' : score < 55 ? 'medium' : 'high'

  const chip = document.getElementById('metaRiskChip')
  chip.textContent = level + ' risk'
  chip.className = 'meta-risk-chip chip-' + level

  // File info pills
  const fi = data.file_info || {}
  const infoEl = document.getElementById('metaFileInfo')
  infoEl.innerHTML = ''
  const pills = [fi.filename, fi.filetype, fi.mime, fi.size, fi.dimensions].filter(Boolean)
  pills.forEach(p => {
    const s = document.createElement('span'); s.className = 'meta-info-pill'; s.textContent = p; infoEl.appendChild(s)
  })

  // Sections
  const sectionsEl = document.getElementById('metaSections')
  sectionsEl.innerHTML = ''
  const findings = data.findings || {}
  const hasSensitive = Object.keys(findings).length > 0

  if (!hasSensitive) {
    sectionsEl.innerHTML = '<div class="page-clean" style="margin-bottom:12px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>No sensitive metadata found in this file</div>'
  } else {
    Object.entries(findings).forEach(([cat, fields]) => {
      if (!Object.keys(fields).length) return
      const isDanger = CAT_DANGER.has(cat)
      const sec = document.createElement('div'); sec.className = 'meta-section'
      sec.innerHTML = `<div class="meta-section-label">${CAT_LABELS[cat] || cat}</div>`
      const rows = document.createElement('div'); rows.className = 'meta-rows'
      Object.entries(fields).forEach(([k, v]) => {
        const row = document.createElement('div')
        row.className = 'meta-row ' + (isDanger ? 'danger' : 'sensitive')
        row.innerHTML = `<span class="meta-key">${k}</span><span class="meta-val">${v}</span>`
        rows.appendChild(row)
      })
      sec.appendChild(rows)

      // GPS map link
      if (cat === 'gps' && data.gps_summary) {
        const parts = data.gps_summary.split(',')
        if (parts.length >= 2) {
          const lat = encodeURIComponent(parts[0].trim())
          const lon = encodeURIComponent(parts[1].trim())
          sec.innerHTML += `<div class="meta-gps-map">
            <a class="meta-gps-link" href="https://maps.google.com/?q=${lat},${lon}" target="_blank">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="10" r="3"/><path d="M12 2a8 8 0 00-8 8c0 5.4 7.4 13.5 7.7 13.8a.4.4 0 00.6 0C12.6 23.5 20 15.4 20 10a8 8 0 00-8-8z"/></svg>
              View on Google Maps
            </a>
          </div>`
        }
      }
      sectionsEl.appendChild(sec)
    })
  }

  if (data.extraction_error) {
    const warn = document.createElement('div')
    warn.className = 'meta-strip-warn'
    warn.textContent = 'Deep metadata extraction unavailable: ' + data.extraction_error + '. Showing basic file details.'
    sectionsEl.prepend(warn)
  }

  // Risk flags summary
  if ((data.risk_flags||[]).length) {
    const flagsDiv = document.createElement('div')
    flagsDiv.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px'
    data.risk_flags.forEach(f => {
      const s = document.createElement('span'); s.className = 'flag'; s.textContent = f; flagsDiv.appendChild(s)
    })
    sectionsEl.prepend(flagsDiv)
  }

  // AI box
  const aiBoxEl = document.getElementById('metaAiBox')
  aiBoxEl.innerHTML = ''
  const ai = data.ai_analysis
  if (ai && ai.available && ai.summary) {
    let html = `<div class="meta-ai-box">
      <div class="meta-ai-summary">${ai.summary}</div>`
    if ((ai.privacy_risks||[]).length) {
      html += `<div class="meta-ai-risks">`
      ai.privacy_risks.forEach(r => { html += `<div class="meta-ai-risk">âš  ${r}</div>` })
      html += `</div>`
    }
    if (ai.journalist_advice) {
      html += `<div class="meta-ai-advice">${ai.journalist_advice}</div>`
    }
    html += `</div>`

    if (ai.strip_metadata) {
      html += `<div class="meta-strip-warn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Strip metadata before sharing or publishing this file.
      </div>`
    }
    aiBoxEl.innerHTML = html
  }

  // All fields table
  const allFields = data.all_fields || {}
  const tableEl = document.getElementById('metaAllTable')
  tableEl.innerHTML = Object.entries(allFields).map(([k,v]) =>
    `<div class="meta-all-row"><span class="meta-all-key">${k}</span><span class="meta-all-val">${v}</span></div>`
  ).join('')

  card.classList.add('show')
}

function toggleAllFields() {
  const t = document.getElementById('metaAllTable')
  const btn = document.querySelector('.meta-all-btn')
  const open = t.classList.toggle('show')
  btn.textContent = open ? 'Hide all fields' : 'Show all fields'
}

// ---------- History ----------

const dotColors = {clean:'#16a34a', low:'#ca8a04', medium:'#ea580c', high:'#dc2626', unknown:'#a8a8a4'}

function addHistory(url, score) {
  const {level} = levelInfo(score)
  const list  = document.getElementById('historyList')
  const short = url.replace(/^https?:\/\//,'').slice(0,26)
  historyItems.unshift({url, level, short, type: 'url'})
  renderHistory()
}

function addHistoryFile(name, score) {
  const level = score === 0 ? 'clean' : score < 25 ? 'low' : score < 55 ? 'medium' : 'high'
  historyItems.unshift({label: name.slice(0,26), level, type: 'file'})
  renderHistory()
}

function renderHistory() {
  const list = document.getElementById('historyList')
  list.innerHTML = historyItems.slice(0,14).map((h,i) =>
    `<div class="history-item ${i===0?'active':''}" onclick="loadFromHistory(${i})" title="${h.url||h.label}">
      <span class="history-dot" style="background:${dotColors[h.level]}"></span>${h.short||h.label}
    </div>`
  ).join('')
}

function loadFromHistory(idx) {
  const item = historyItems[idx]
  if (!item) return
  if (item.type === 'url') {
    switchMode('url')
    document.getElementById('urlInput').value = item.url
    document.querySelectorAll('.history-item').forEach((el,i) => el.classList.toggle('active', i===idx))
    closeSidebar()
    analyze()
  } else {
    closeSidebar()
  }
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key==='Enter') analyze()
})
