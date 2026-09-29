(() => {
  'use strict';

  const VERSION = 'domain-tool-ui-v1';
  const ORIGINAL_FETCH = window.fetch.bind(window);
  const state = {
    sessionToken: '',
    enabled: true,
    mode: 'automatic',
    documents: [],
    selected: new Set(),
    uploadDomain: 'shared',
    busy: false,
    lastRag: null
  };

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function displayName(name) {
    // Client-side converted-document convention can be added later.
    // Backend-supported extensions are shown unchanged.
    return String(name || 'document');
  }

  function pathOf(input) {
    try {
      const raw = typeof input === 'string' ? input : input.url;
      return new URL(raw, window.location.href).pathname;
    } catch {
      return '';
    }
  }

  function cloneHeaders(headersLike) {
    const out = new Headers(headersLike || {});
    if (state.sessionToken && !out.has('X-Jeffrey-Session')) {
      out.set('X-Jeffrey-Session', state.sessionToken);
    }
    return out;
  }

  const DOMAIN_LABELS = {
    soc: 'SOC',
    iso: 'ISO',
    shared: 'Gedeeld',
    general: 'Algemeen'
  };

  function normalizeDocDomain(value) {
    const domain = String(value || 'shared').toLowerCase();
    return ['soc', 'iso', 'shared'].includes(domain) ? domain : 'shared';
  }

  function domainLabel(value) {
    return DOMAIN_LABELS[String(value || '').toLowerCase()] || 'Gedeeld';
  }

  function lastUserText(messages) {
    if (!Array.isArray(messages)) return '';
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i];
      if (!msg || msg.role !== 'user') continue;
      if (typeof msg.content === 'string') return msg.content;
      if (Array.isArray(msg.content)) {
        return msg.content
          .filter(part => part && part.type === 'text' && typeof part.text === 'string')
          .map(part => part.text)
          .join('\n');
      }
    }
    return '';
  }

  function oneLine(value, max = 800) {
    return String(value || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, max);
  }

  function lineValue(text, label) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m = String(text || '').match(new RegExp(`^\\s*${escaped}\\s*:\\s*(.+)$`, 'mi'));
    return m ? oneLine(m[1]) : '';
  }

  function quotedAfter(text, label) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m = String(text || '').match(
      new RegExp(`${escaped}\\s*:\\s*(?:\\n\\s*)?"([^"]+)"`, 'i')
    );
    return m ? oneLine(m[1]) : '';
  }

  function compactQuery(parts) {
    const seen = new Set();
    const clean = [];
    for (const part of parts) {
      const value = oneLine(part);
      if (!value) continue;
      const key = value.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      clean.push(value);
    }
    return clean.join(' | ').slice(0, 2400);
  }

  function classifyToolContext(messages) {
    const prompt = lastUserText(messages);
    if (!prompt) {
      return {tool: 'general_chat', knowledgeDomain: 'general', retrievalQuery: ''};
    }

    // ISO tools
    if (
      prompt.includes('voor informatiebeveiliging over het onderwerp "') &&
      prompt.includes('VUL DE STRUCTUUR IN MET:')
    ) {
      return {
        tool: 'policy_generator',
        knowledgeDomain: 'iso',
        retrievalQuery: compactQuery([
          'informatiebeveiligingsbeleid',
          lineValue(prompt, '- Onderwerp'),
          lineValue(prompt, '- Reikwijdte'),
          lineValue(prompt, '- Context'),
          lineValue(prompt, '- Frameworks')
        ])
      };
    }

    if (prompt.startsWith('Voer een informatiebeveiliging risicoanalyse uit voor:')) {
      const asset = (prompt.match(/risicoanalyse uit voor:\s*"([^"]+)"/i) || [])[1] || '';
      return {
        tool: 'risk_analysis',
        knowledgeDomain: 'iso',
        retrievalQuery: compactQuery([
          'informatiebeveiliging risicoanalyse',
          asset,
          lineValue(prompt, '- Type analyse'),
          lineValue(prompt, '- Kriticaliteit'),
          lineValue(prompt, '- Scope'),
          lineValue(prompt, '- Bekende dreigingen/zorgen'),
          prompt.includes('BIO2') ? 'BIO2' : '',
          prompt.includes('ISO 27005') ? 'ISO 27005' : '',
          prompt.includes('NEN 7510') ? 'NEN 7510' : ''
        ])
      };
    }

    if (prompt.startsWith('Schrijf een adviesnotitie vanuit de rol van Information Security Officer')) {
      return {
        tool: 'advice_note',
        knowledgeDomain: 'iso',
        retrievalQuery: compactQuery([
          'informatiebeveiliging adviesnotitie',
          quotedAfter(prompt, 'VRAAG'),
          lineValue(prompt, 'VRAGENSTELLER'),
          lineValue(prompt, 'URGENTIE'),
          lineValue(prompt, 'CONTEXT'),
          lineValue(prompt, 'TOE TE PASSEN KADERS')
        ])
      };
    }

    if (prompt.startsWith('Beantwoord de volgende compliance vraag als een ervaren Information Security Officer')) {
      return {
        tool: 'compliance_qa',
        knowledgeDomain: 'iso',
        retrievalQuery: compactQuery([
          'compliance informatiebeveiliging',
          quotedAfter(prompt, 'VRAAG'),
          lineValue(prompt, 'PRIMAIR FRAMEWORK'),
          lineValue(prompt, 'TYPE VRAAG')
        ])
      };
    }

    // SOC tools
    if (prompt.startsWith('DETECTIE TRIGGER TESTER')) {
      const ruleMatch = prompt.match(/Detectieregel:\s*\n([\s\S]*?)(?:\nExtra context:|\nGeef het antwoord|\n\nGeef het antwoord)/i);
      return {
        tool: 'detection_trigger',
        knowledgeDomain: 'soc',
        retrievalQuery: compactQuery([
          'SOC detectie trigger alert verificatie',
          lineValue(prompt, 'Platform'),
          lineValue(prompt, 'Extra context'),
          oneLine(ruleMatch ? ruleMatch[1] : '', 1000)
        ])
      };
    }

    if (prompt.startsWith('SOAR PLAYBOOK voor ')) {
      const first = prompt.match(/^SOAR PLAYBOOK voor\s+(.+)$/mi);
      return {
        tool: 'soar_playbook',
        knowledgeDomain: 'soc',
        retrievalQuery: compactQuery([
          'SOC SOAR playbook incident response',
          first ? first[1] : '',
          lineValue(prompt, 'Incident'),
          lineValue(prompt, 'Severity'),
          lineValue(prompt, 'Context'),
          lineValue(prompt, 'Acties')
        ])
      };
    }

    if (prompt.startsWith('Sigma analyse voor ')) {
      const first = prompt.match(/^Sigma analyse voor\s+([^:]+):/i);
      const body = prompt
        .replace(/^Sigma analyse voor\s+[^:]+:\s*/i, '')
        .split(/\n\nGeef de volledige geconverteerde query\./i)[0];
      return {
        tool: 'sigma_analysis',
        knowledgeDomain: 'soc',
        retrievalQuery: compactQuery([
          'SOC Sigma detection rule',
          first ? first[1] : '',
          oneLine(body, 1200)
        ])
      };
    }

    if (/^(Suricata|Zeek)\s+DETECTION\b/i.test(prompt)) {
      const engine = (prompt.match(/^(\S+)\s+DETECTION/im) || [])[1] || '';
      return {
        tool: 'network_detection',
        knowledgeDomain: 'soc',
        retrievalQuery: compactQuery([
          'SOC network detection',
          engine,
          lineValue(prompt, 'Threat'),
          lineValue(prompt, 'Protocol'),
          lineValue(prompt, "Context/IOC's")
        ])
      };
    }

    if (prompt.startsWith('FORENSISCHE TRIAGE — Analyse van verdacht bestand')) {
      const suspicious = (
        prompt.match(/VERDACHTE API CALLS \/ KEYWORDS:\s*\n([^\n]+)/i) || []
      )[1] || '';
      return {
        tool: 'forensic_triage',
        knowledgeDomain: 'soc',
        retrievalQuery: compactQuery([
          'SOC forensische triage',
          lineValue(prompt, '- Naam'),
          lineValue(prompt, '- Type'),
          lineValue(prompt, 'CONTEXT'),
          suspicious
        ])
      };
    }

    return {
      tool: 'general_chat',
      knowledgeDomain: 'general',
      retrievalQuery: ''
    };
  }

  function setStatus(message, kind = 'info') {
    const el = document.getElementById('ragKnowledgeStatus');
    if (!el) return;
    el.textContent = message;
    el.dataset.kind = kind;
  }

  function effectiveMode() {
    return state.enabled ? state.mode : 'off';
  }

  function syncControls() {
    const enabled = document.getElementById('ragKnowledgeEnabled');
    if (enabled) enabled.checked = state.enabled;

    document.querySelectorAll('input[name="ragKnowledgeMode"]').forEach(r => {
      r.checked = r.value === state.mode;
      r.disabled = !state.enabled;
    });

    const selectedPanel = document.getElementById('ragKnowledgeDocuments');
    if (selectedPanel) {
      selectedPanel.classList.toggle(
        'rag-selected-mode',
        state.enabled && state.mode === 'selected_documents'
      );
    }

    const uploadDomain = document.getElementById('ragKnowledgeUploadDomain');
    if (uploadDomain) uploadDomain.value = state.uploadDomain;

    const modeLabel = document.getElementById('ragKnowledgeModeLabel');
    if (modeLabel) {
      const names = {
        off: 'Uit',
        automatic: 'Automatisch',
        selected_documents: 'Alleen geselecteerde documenten'
      };
      modeLabel.textContent = state.enabled ? names[state.mode] : 'Uit';
    }
  }

  function renderDocuments() {
    const list = document.getElementById('ragKnowledgeList');
    if (!list) return;

    if (!state.sessionToken) {
      list.innerHTML = '<div class="rag-empty">Log in om knowledge te laden.</div>';
      return;
    }

    if (state.documents.length === 0) {
      list.innerHTML = '<div class="rag-empty">Nog geen knowledge documenten.</div>';
      return;
    }

    list.innerHTML = state.documents.map(doc => {
      const checked = state.selected.has(doc.document_id) ? 'checked' : '';
      const kb = Math.max(1, Math.round((doc.size_bytes || 0) / 1024));
      const domain = normalizeDocDomain(doc.domain);
      return `
        <div class="rag-doc-row" data-doc-id="${esc(doc.document_id)}" data-domain="${esc(domain)}">
          <label class="rag-doc-select">
            <input type="checkbox" class="rag-doc-checkbox"
                   data-doc-id="${esc(doc.document_id)}" ${checked}>
            <span class="rag-domain-badge rag-domain-${esc(domain)}">${esc(domainLabel(domain))}</span>
            <span class="rag-doc-name" title="${esc(doc.filename)}">${esc(displayName(doc.filename))}</span>
          </label>
          <span class="rag-doc-meta">${kb} KB · ${Number(doc.chunk_count || 0)} chunks</span>
          <button type="button" class="rag-doc-delete"
                  data-doc-id="${esc(doc.document_id)}"
                  data-doc-name="${esc(doc.filename)}"
                  title="Verwijder knowledge document">✕</button>
        </div>`;
    }).join('');

    list.querySelectorAll('.rag-doc-checkbox').forEach(cb => {
      cb.addEventListener('change', () => {
        const id = cb.dataset.docId;
        if (cb.checked) state.selected.add(id);
        else state.selected.delete(id);
        syncControls();
      });
    });

    list.querySelectorAll('.rag-doc-delete').forEach(btn => {
      btn.addEventListener('click', () => {
        deleteDocument(btn.dataset.docId, btn.dataset.docName);
      });
    });
  }

  async function loadDocuments() {
    if (!state.sessionToken) return;
    try {
      const res = await ORIGINAL_FETCH('/api/rag/documents', {
        method: 'GET',
        headers: {'X-Jeffrey-Session': state.sessionToken},
        cache: 'no-store'
      });
      if (res.status === 401) {
        state.sessionToken = '';
        state.documents = [];
        state.selected.clear();
        renderDocuments();
        setStatus('Knowledge sessie verlopen.', 'error');
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const currentIds = new Set((data.documents || []).map(d => d.document_id));
      for (const id of Array.from(state.selected)) {
        if (!currentIds.has(id)) state.selected.delete(id);
      }
      state.documents = data.documents || [];
      renderDocuments();
      setStatus(`${state.documents.length} knowledge document${state.documents.length === 1 ? '' : 'en'} beschikbaar.`, 'ok');
    } catch (err) {
      setStatus(`Knowledge-lijst laden mislukt: ${err.message}`, 'error');
    }
  }

  async function fileToBase64(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    const step = 0x8000;
    for (let i = 0; i < bytes.length; i += step) {
      binary += String.fromCharCode(...bytes.subarray(i, i + step));
    }
    return btoa(binary);
  }

  async function uploadDocument(file) {
    if (!state.sessionToken) {
      alert('Log eerst in voordat je een knowledge document uploadt.');
      return;
    }

    const allowed = /\.(txt|md|json|csv|ya?ml)$/i;
    if (!allowed.test(file.name)) {
      alert(
        'Dit bestandstype kan nog niet persistent in de knowledge base worden geïndexeerd.\n\n' +
        'Ondersteund: TXT, MD, JSON, CSV, YAML/YML.\n' +
        'PDF/DOCX/XLSX blijven uitgeschakeld omdat daarvoor op de server nog geen goedgekeurde parser aanwezig is.'
      );
      return;
    }

    if (file.size <= 0) {
      alert('Leeg document kan niet worden toegevoegd.');
      return;
    }
    if (file.size > 16 * 1024 * 1024) {
      alert('Knowledge document is te groot (maximaal 16 MB).');
      return;
    }

    state.busy = true;
    setStatus(`Uploaden en indexeren: ${file.name}...`, 'info');

    try {
      const contentBase64 = await fileToBase64(file);
      const res = await ORIGINAL_FETCH('/api/rag/documents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Jeffrey-Session': state.sessionToken
        },
        body: JSON.stringify({
          filename: file.name,
          content_base64: contentBase64,
          domain: state.uploadDomain
        })
      });

      const text = await res.text();
      let data = {};
      try { data = JSON.parse(text); } catch {}

      if (!res.ok) {
        const code = data?.error?.code || data?.error || `HTTP ${res.status}`;
        const msg = data?.error?.message || data?.message || text || code;
        if (String(code).includes('duplicate_document')) {
          throw new Error('dit document staat al in de knowledge base');
        }
        throw new Error(msg);
      }

      const newId = data?.document?.document_id;
      if (newId) state.selected.add(newId);
      await loadDocuments();
      setStatus(`${file.name} is opgeslagen als ${domainLabel(state.uploadDomain)} en geïndexeerd.`, 'ok');
    } catch (err) {
      setStatus(`Upload mislukt: ${err.message}`, 'error');
      alert(`Knowledge upload mislukt: ${err.message}`);
    } finally {
      state.busy = false;
    }
  }

  async function deleteDocument(documentId, filename) {
    if (!state.sessionToken) return;
    if (!/^[0-9a-f]{32}$/.test(documentId || '')) return;

    if (!confirm(`Knowledge document verwijderen?\n\n${filename}\n\nDit verwijdert het document persistent uit de lokale knowledge base.`)) {
      return;
    }

    try {
      const res = await ORIGINAL_FETCH(`/api/rag/documents/${encodeURIComponent(documentId)}`, {
        method: 'DELETE',
        headers: {'X-Jeffrey-Session': state.sessionToken}
      });
      if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try {
          const data = await res.json();
          detail = data?.error?.message || detail;
        } catch {}
        throw new Error(detail);
      }
      state.selected.delete(documentId);
      await loadDocuments();
      setStatus(`${filename} verwijderd.`, 'ok');
    } catch (err) {
      setStatus(`Verwijderen mislukt: ${err.message}`, 'error');
    }
  }

  function renderRagSources(rag) {
    state.lastRag = rag;
    if (!rag) return;

    const messages = document.querySelectorAll('.message.assistant');
    const message = messages[messages.length - 1];
    if (!message) return;

    const wrapper = message.querySelector('.message-content-wrapper');
    if (!wrapper) return;

    let box = wrapper.querySelector('.rag-answer-sources');
    if (!box) {
      box = document.createElement('div');
      box.className = 'rag-answer-sources';
      wrapper.appendChild(box);
    }

    if (!rag.retrieval_used) {
      box.innerHTML = '<span class="rag-source-state">Knowledge: uit</span>';
      return;
    }

    if (!rag.matched || !Array.isArray(rag.sources) || rag.sources.length === 0) {
      box.innerHTML = '<span class="rag-source-state">Knowledge: geen relevante bron gebruikt</span>';
      return;
    }

    const scope = rag.knowledge_domain && rag.knowledge_domain !== 'general'
      ? ` · ${domainLabel(rag.knowledge_domain)} + Gedeeld`
      : '';
    box.innerHTML = `
      <span class="rag-source-state">Knowledge bronnen${esc(scope)}:</span>
      ${rag.sources.map(s => {
        const domain = normalizeDocDomain(s.domain);
        return `
          <span class="rag-source-chip" title="chunk ${Number(s.chunk_no ?? 0)}">
            <span class="rag-source-domain">${esc(domainLabel(domain))}</span>
            ${esc(s.source_id)} · ${esc(displayName(s.filename))}
          </span>`;
      }).join('')}
    `;
  }

  async function inspectRagResponse(response) {
    try {
      const clone = response.clone();
      const type = (clone.headers.get('Content-Type') || '').toLowerCase();

      if (type.includes('application/json')) {
        const data = await clone.json();
        if (data?.rag) renderRagSources(data.rag);
        return;
      }

      if (!type.includes('text/event-stream') || !clone.body) return;

      const reader = clone.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, {stream: true});

        const events = buffer.split(/\n\n/);
        buffer = events.pop() || '';

        for (const event of events) {
          const dataLine = event.split(/\r?\n/).find(line => line.startsWith('data: '));
          if (!dataLine || dataLine === 'data: [DONE]') continue;
          try {
            const data = JSON.parse(dataLine.slice(6));
            if (data?.rag) {
              renderRagSources(data.rag);
              try { await reader.cancel(); } catch {}
              return;
            }
          } catch {}
        }
      }
    } catch (err) {
      console.warn(`[${VERSION}] source metadata inspection failed`, err);
    }
  }

  async function interceptFetch(input, init = {}) {
    const path = pathOf(input);

    // Capture the existing session token without changing the login request.
    if (path === '/api/login') {
      const response = await ORIGINAL_FETCH(input, init);
      if (response.ok) {
        try {
          const data = await response.clone().json();
          if (typeof data.session_token === 'string' && data.session_token) {
            state.sessionToken = data.session_token;
            setTimeout(loadDocuments, 0);
          }
        } catch {}
      }
      return response;
    }

    if (path === '/api/logout') {
      const response = await ORIGINAL_FETCH(input, init);
      state.sessionToken = '';
      state.documents = [];
      state.selected.clear();
      state.lastRag = null;
      renderDocuments();
      setStatus('Uitgelogd.', 'info');
      return response;
    }

    // Keep every non-chat request completely untouched.
    if (path !== '/api/chat' || effectiveMode() === 'off') {
      return ORIGINAL_FETCH(input, init);
    }

    // Current Jeffrey frontend uses a string URL + JSON body for /api/chat.
    // If this contract ever changes, fail safe to the existing route.
    if (typeof input !== 'string' || typeof init?.body !== 'string') {
      return ORIGINAL_FETCH(input, init);
    }

    let body;
    try {
      body = JSON.parse(init.body);
    } catch {
      return ORIGINAL_FETCH(input, init);
    }

    if (!body || !Array.isArray(body.messages)) {
      return ORIGINAL_FETCH(input, init);
    }

    const mode = effectiveMode();
    if (mode === 'selected_documents' && state.selected.size === 0) {
      throw new Error('Knowledge mode staat op "Alleen geselecteerde documenten", maar er is geen document geselecteerd.');
    }

    body.knowledge_mode = mode;
    body.document_ids = mode === 'selected_documents' ? Array.from(state.selected) : [];

    const toolContext = classifyToolContext(body.messages);
    body.knowledge_domain = toolContext.knowledgeDomain;
    if (toolContext.retrievalQuery) {
      body.retrieval_query = toolContext.retrievalQuery;
    }

    const ragInit = {
      ...init,
      headers: cloneHeaders(init.headers),
      body: JSON.stringify(body)
    };

    const response = await ORIGINAL_FETCH('/api/rag/chat', ragInit);
    inspectRagResponse(response);
    return response;
  }

  function installStyles() {
    const style = document.createElement('style');
    style.id = 'ragKnowledgeUiStyles';
    style.textContent = `
      .rag-knowledge-section { padding:16px 20px; border-bottom:1px solid var(--border); }
      .rag-knowledge-header { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:10px; }
      .rag-knowledge-title { font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-dim); }
      .rag-mode-badge { font-size:10px; padding:2px 7px; border-radius:999px; background:var(--accent-dim); color:var(--accent); border:1px solid var(--accent-light); }
      .rag-enabled { display:flex; align-items:center; gap:7px; font-size:12px; font-weight:600; margin-bottom:10px; cursor:pointer; }
      .rag-enabled input, .rag-radio input, .rag-doc-select input { accent-color:var(--accent); }
      .rag-modes { display:flex; flex-direction:column; gap:6px; margin-bottom:10px; }
      .rag-radio { display:flex; gap:7px; align-items:center; font-size:12px; cursor:pointer; }
      .rag-upload-domain-wrap { display:flex; align-items:center; justify-content:space-between; gap:8px; margin:8px 0 7px; font-size:11px; color:var(--text-dim); }
      .rag-upload-domain { flex:1; min-width:0; padding:6px 7px; border:1px solid var(--border); border-radius:7px; background:var(--bg-tertiary); color:var(--text); font-size:11px; }
      .rag-upload-btn { width:100%; padding:8px; border:1px solid var(--border); border-radius:var(--radius-md); background:var(--bg-tertiary); cursor:pointer; font-size:12px; font-weight:600; }
      .rag-upload-btn:hover { background:var(--bg-hover); }
      .rag-knowledge-list { margin-top:10px; display:flex; flex-direction:column; gap:6px; }
      .rag-doc-row { padding:7px; border:1px solid var(--border); border-radius:8px; background:var(--bg-tertiary); position:relative; }
      .rag-doc-select { display:flex; align-items:center; gap:6px; padding-right:22px; cursor:pointer; min-width:0; }
      .rag-domain-badge { flex:0 0 auto; font-size:8px; line-height:1; padding:3px 5px; border-radius:999px; border:1px solid var(--border); font-weight:800; letter-spacing:.03em; }
      .rag-domain-soc { background:rgba(239,68,68,.09); }
      .rag-domain-iso { background:rgba(59,130,246,.09); }
      .rag-domain-shared { background:rgba(16,185,129,.09); }
      .rag-doc-name { font-size:11px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .rag-doc-meta { display:block; font-size:9px; color:var(--text-dim); margin:3px 22px 0 20px; }
      .rag-doc-delete { position:absolute; top:6px; right:5px; border:0; background:transparent; color:var(--text-dim); cursor:pointer; font-size:12px; }
      .rag-doc-delete:hover { color:var(--error); }
      .rag-empty { color:var(--text-dim); font-size:11px; line-height:1.4; }
      .rag-status { margin-top:8px; font-size:10px; line-height:1.35; color:var(--text-dim); }
      .rag-status[data-kind="error"] { color:var(--error); }
      .rag-status[data-kind="ok"] { color:var(--success); }
      .rag-selected-mode .rag-doc-row { border-color:var(--accent-light); }
      .rag-answer-sources { display:flex; flex-wrap:wrap; gap:5px; align-items:center; margin-top:4px; font-size:10px; color:var(--text-dim); }
      .rag-source-state { font-weight:600; }
      .rag-source-chip { padding:2px 7px; border-radius:999px; background:var(--accent-dim); border:1px solid var(--accent-light); color:var(--accent-hover); }
      .rag-source-domain { font-weight:800; margin-right:3px; }
      .sidebar.collapsed .rag-knowledge-section { display:none; }
    `;
    document.head.appendChild(style);
  }

  function installUi() {
    if (document.getElementById('ragKnowledgeSection')) return;

    const sidebarContent = document.querySelector('.sidebar-content');
    if (!sidebarContent) {
      console.warn(`[${VERSION}] .sidebar-content not found`);
      return;
    }

    const section = document.createElement('div');
    section.className = 'rag-knowledge-section';
    section.id = 'ragKnowledgeSection';
    section.innerHTML = `
      <div class="rag-knowledge-header">
        <span class="rag-knowledge-title">🧠 Knowledge</span>
        <span class="rag-mode-badge" id="ragKnowledgeModeLabel">Automatisch</span>
      </div>

      <label class="rag-enabled">
        <input type="checkbox" id="ragKnowledgeEnabled" checked>
        Gebruik knowledge base
      </label>

      <div class="rag-modes">
        <label class="rag-radio"><input type="radio" name="ragKnowledgeMode" value="off"> Uit</label>
        <label class="rag-radio"><input type="radio" name="ragKnowledgeMode" value="automatic" checked> Automatisch</label>
        <label class="rag-radio"><input type="radio" name="ragKnowledgeMode" value="selected_documents"> Alleen geselecteerde documenten</label>
      </div>

      <div class="rag-upload-domain-wrap">
        <label for="ragKnowledgeUploadDomain">Upload domein</label>
        <select id="ragKnowledgeUploadDomain" class="rag-upload-domain" title="Domein wordt persistent aan het document gekoppeld">
          <option value="shared" selected>Gedeeld</option>
          <option value="soc">SOC</option>
          <option value="iso">ISO</option>
        </select>
      </div>

      <button type="button" class="rag-upload-btn" id="ragKnowledgeUploadBtn">＋ Upload document</button>
      <input type="file" id="ragKnowledgeUploadInput" hidden
             accept=".txt,.md,.json,.csv,.yaml,.yml,text/plain,text/markdown,application/json,text/csv">

      <div class="rag-knowledge-list" id="ragKnowledgeList">
        <div class="rag-empty">Log in om knowledge te laden.</div>
      </div>
      <div class="rag-status" id="ragKnowledgeStatus">Persistente lokale knowledge · geen chat-memory</div>
    `;

    const newChatSection = Array.from(sidebarContent.querySelectorAll('.sidebar-section'))
      .find(el => el.querySelector('.new-chat-btn'));

    if (newChatSection) sidebarContent.insertBefore(section, newChatSection);
    else sidebarContent.appendChild(section);

    document.getElementById('ragKnowledgeEnabled').addEventListener('change', e => {
      state.enabled = e.target.checked;
      if (state.enabled && state.mode === 'off') state.mode = 'automatic';
      syncControls();
    });

    document.querySelectorAll('input[name="ragKnowledgeMode"]').forEach(r => {
      r.addEventListener('change', () => {
        if (!r.checked) return;
        state.mode = r.value;
        state.enabled = r.value !== 'off';
        syncControls();
      });
    });

    document.getElementById('ragKnowledgeUploadDomain').addEventListener('change', e => {
      const value = String(e.target.value || 'shared').toLowerCase();
      state.uploadDomain = ['soc', 'iso', 'shared'].includes(value) ? value : 'shared';
      syncControls();
    });

    document.getElementById('ragKnowledgeUploadBtn').addEventListener('click', () => {
      if (state.busy) return;
      document.getElementById('ragKnowledgeUploadInput').click();
    });

    document.getElementById('ragKnowledgeUploadInput').addEventListener('change', async e => {
      const file = e.target.files?.[0];
      e.target.value = '';
      if (file) await uploadDocument(file);
    });

    syncControls();
  }

  function init() {
    installStyles();
    installUi();
    window.fetch = interceptFetch;
    Object.defineProperty(window, '__jeffreyRagUi', {
      value: Object.freeze({
        version: VERSION,
        classifyToolContext: messages => ({...classifyToolContext(messages)})
      }),
      writable: false,
      configurable: false
    });
    console.info(`[${VERSION}] loaded`);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once: true});
  } else {
    init();
  }
})();
