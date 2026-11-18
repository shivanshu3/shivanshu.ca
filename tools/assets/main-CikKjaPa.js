(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),t.credentials=e.crossOrigin===`use-credentials`?`include`:e.crossOrigin===`anonymous`?`omit`:`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();var e={a:`Alfa`,b:`Bravo`,c:`Charlie`,d:`Delta`,e:`Echo`,f:`Foxtrot`,g:`Golf`,h:`Hotel`,i:`India`,j:`Juliett`,k:`Kilo`,l:`Lima`,m:`Mike`,n:`November`,o:`Oscar`,p:`Papa`,q:`Quebec`,r:`Romeo`,s:`Sierra`,t:`Tango`,u:`Uniform`,v:`Victor`,w:`Whiskey`,x:`X-ray`,y:`Yankee`,z:`Zulu`},t={0:`Zero`,1:`One`,2:`Two`,3:`Three`,4:`Four`,5:`Five`,6:`Six`,7:`Seven`,8:`Eight`,9:`Nine`," ":`Space`,"\n":`New line`,"	":`Tab`,".":`Dot`,",":`Comma`,"-":`Hyphen`,_:`Underscore`,"@":`At sign`,"/":`Slash`,"\\":`Backslash`,":":`Colon`,";":`Semicolon`,"!":`Exclamation mark`,"?":`Question mark`,"#":`Hash`,$:`Dollar sign`,"%":`Percent`,"&":`Ampersand`,"*":`Asterisk`,"+":`Plus`,"=":`Equals`,"(":`Open parenthesis`,")":`Close parenthesis`,"[":`Open bracket`,"]":`Close bracket`,"{":`Open brace`,"}":`Close brace`,"<":`Less than`,">":`Greater than`,"'":`Apostrophe`,'"':`Double quote`,"`":`Backtick`,"~":`Tilde`,"^":`Caret`,"|":`Vertical bar`};function n(e){return e.replace(/\r\n?/g,`
`).normalize(`NFC`).toLowerCase().normalize(`NFC`)}function r(r){return Array.from(n(r),n=>({character:n,display:n===` `?`␣`:n===`
`?`↵`:n===`	`?`⇥`:n,word:e[n]??t[n]??`U+${n.codePointAt(0).toString(16).toUpperCase().padStart(4,`0`)}`,kind:e[n]?`letter`:t[n]?`symbol`:`unmapped`}))}function i(e){let t=4294967295;for(let r of new TextEncoder().encode(n(e))){t^=r;for(let e=0;e<8;e++)t=t>>>1^(t&1?3988292384:0)}return String(((t^4294967295)>>>0)%1e3).padStart(3,`0`)}var a=document.body.dataset.page??`home`,o=`/tools/`,s={spell:`<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 6h10M9 4v2c0 7-5 10-5 10m9-6c-1 3-4 5-7 6m8 4 4-11 4 11m-6.5-4h5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,type:`<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 6V4h12v2M9 4v16M6 20h6m3-7c0-3 6-3 6 0v7m0-6c-8-2-8 7 0 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,lock:`<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="3" stroke="currentColor" stroke-width="1.6"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`},c=`
  <section class="intro home-intro">
    <p class="eyebrow">A little less friction.</p>
    <h1>Small tools.<br><span>Everyday useful.</span></h1>
    <p class="lede">A growing collection of simple things that make life a little easier.</p>
  </section>
  <div class="tool-grid">
    <a class="tool-card" href="${o}spell-it/">
      <span class="tool-icon">${s.spell}</span>
      <h2>Spell It</h2>
      <p>“S as in Sierra.” Spell anything over the phone, with a checksum to double-check it.</p>
      <div class="card-example" aria-hidden="true"><span>s <b>Sierra</b></span><span>g <b>Golf</b></span></div>
      <span class="card-action">Open Spell It</span>
    </a>
    <a class="tool-card" href="${o}clear-type/">
      <span class="tool-icon">${s.type}</span>
      <h2>Clear Type</h2>
      <p>Is that a zero or an O? See your text in a font that gives each character its own shape.</p>
      <div class="card-example character-example" aria-hidden="true">i l I 1 <span>o O 0</span></div>
      <span class="card-action">Open Clear Type</span>
    </a>
  </div>
  <p class="collection-note">Two tools for now. More as the need arises.</p>`,l=`
  <section class="intro">
    <p class="eyebrow">Make yourself understood.</p>
    <h1>Spell It<span class="title-dot">.</span></h1>
    <p class="lede">Turn text into the NATO phonetic alphabet.<br> Handy when you’re spelling something over the phone.</p>
  </section>
  <section class="workspace" aria-label="Phonetic spelling tool">
    <div class="input-heading"><label for="spell-input">What are we spelling?</label><button class="text-button" id="clear" type="button" disabled>Clear</button></div>
    <textarea id="spell-input" class="spell-input mono" rows="2" maxlength="1000" placeholder="a name, an email, a booking code…" autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="input-help"></textarea>
    <div class="input-meta"><p id="input-help">Everything is converted to lowercase.</p><span id="count">0 / 1,000</span></div>
    <div class="empty-state" id="empty"><span class="empty-letters mono" aria-hidden="true">a <span>Alfa</span></span><p>Your phonetic spelling will appear here.</p><button class="text-button" id="example" type="button">Try an example</button></div>
    <section id="results" aria-label="Phonetic spelling" hidden>
      <div class="result-heading"><h2>Read it out</h2><button id="copy" class="secondary-button" type="button">Copy spelling</button></div>
      <ol id="spelling" class="spelling-grid"></ol>
      <p id="unmapped" class="note" hidden>Some characters have no NATO word. Their Unicode codes are shown so they aren’t skipped.</p>
      <div class="checksum-box"><div><h2>3-digit checksum</h2><p>Have the other person enter what they heard here, then compare these digits.</p></div><div class="checksum-value"><output id="checksum" class="mono" aria-label="Checksum"></output><span id="checksum-words"></span></div></div>
    </section>
    <details class="explanation"><summary>How the checksum works</summary><p>It checks the lowercase text, including every space, punctuation mark, and line break. Uppercase and lowercase versions match. Accented characters stay accented.</p><p>A matching checksum helps catch mistakes, but different text can share the same three digits. It is not a security check.</p></details>
  </section>`,u=`
  <section class="intro">
    <p class="eyebrow">Every character, clear.</p>
    <h1>Clear Type<span class="title-dot">.</span></h1>
    <p class="lede">Give similar-looking letters and numbers some space.<br> Type or paste text to see the difference.</p>
  </section>
  <section class="workspace" aria-label="Clear text tool">
    <div class="input-heading"><label for="clear-input">Your text, easier to read</label><button class="text-button" id="clear" type="button" disabled>Clear</button></div>
    <textarea id="clear-input" class="clear-input mono" rows="6" placeholder="Type or paste here…" autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="font-help"></textarea>
    <div class="clear-toolbar"><label class="size-control" for="font-size">Text size <input id="font-size" type="range" min="20" max="56" value="32" step="2"><output id="size-value" for="font-size">32 px</output></label><button id="copy" class="secondary-button" type="button" disabled>Copy text</button></div>
    <div class="character-key" aria-label="Character examples"><div><span class="mono">i l I 1</span><p>i · el · capital i · one</p></div><div><span class="mono">o O 0</span><p>o · capital o · zero</p></div></div>
    <p id="font-help" class="font-note">Set in <a href="https://www.brailleinstitute.org/freefont/" target="_blank" rel="noopener noreferrer">Atkinson Hyperlegible Mono</a>, designed to make characters easier to tell apart. Your text stays exactly as you enter it.</p>
    <p id="font-status" class="note" role="status" hidden>The reading font couldn’t load. Reload the page to try again; character shapes may differ until it loads.</p>
  </section>`;document.querySelector(`#app`).innerHTML=`
  <a class="skip-link" href="#main">Skip to content</a>
  <div class="site-shell">
    <header class="site-header"><a class="brand" href="/">shivanshu<span>.ca</span></a><span class="header-divider" aria-hidden="true">/</span><a class="tools-link" href="${o}" ${a===`home`?`aria-current="page"`:``}>tools</a><nav aria-label="Tools"><a href="${o}spell-it/" ${a===`spell-it`?`aria-current="page"`:``}>Spell It</a><a href="${o}clear-type/" ${a===`clear-type`?`aria-current="page"`:``}>Clear Type</a></nav></header>
    <main id="main">${a===`home`?c:a===`spell-it`?l:u}</main>
    <footer><p>${s.lock}<span>Just your browser. Nothing saved or sent.</span></p><a href="/">Made by Shivanshu</a></footer>
    <p class="toast" id="status" role="status" aria-live="polite"></p>
  </div>`;function d(e){return document.getElementById(e)}var f;function p(e){let t=d(`status`);t.textContent=e,t.classList.add(`visible`),clearTimeout(f),f=setTimeout(()=>t.classList.remove(`visible`),4e3)}async function m(e){try{await navigator.clipboard.writeText(e),p(`Copied to clipboard.`)}catch{p(`Copy is unavailable. Select the text and copy it manually.`)}}if(a===`spell-it`){let e=d(`spell-input`),t=d(`clear`),a=d(`copy`),o=``;function s(){let a=e.value,s=n(a);if(a!==s){let t=n(a.slice(0,e.selectionStart)).length,r=n(a.slice(0,e.selectionEnd)).length,i=e.selectionDirection;e.value=s,e.setSelectionRange(t,r,i)}let c=r(s);d(`count`).textContent=`${c.length.toLocaleString(`en-US`)} / 1,000`,t.disabled=!s,d(`empty`).hidden=!!s,d(`results`).hidden=!s,d(`unmapped`).hidden=!c.some(e=>e.kind===`unmapped`);let l=document.createDocumentFragment();for(let e of c){let t=document.createElement(`li`);t.className=`spelling-token ${e.kind}`;let n=document.createElement(`span`);n.className=`token-character mono`,n.textContent=e.display,n.setAttribute(`aria-hidden`,`true`);let r=document.createElement(`span`);r.textContent=e.word,t.append(n,r),l.append(t)}d(`spelling`).replaceChildren(l);let u=i(s);d(`checksum`).textContent=s?u:``,d(`checksum-words`).textContent=Array.from(u,e=>r(e)[0].word.toLowerCase()).join(` · `),o=`${c.map(e=>e.word).join(` · `)}\nChecksum: ${u}`}e.addEventListener(`input`,e=>{e.isComposing||s()}),e.addEventListener(`compositionend`,s),t.addEventListener(`click`,()=>{e.value=``,s(),e.focus()}),a.addEventListener(`click`,()=>{m(o)}),d(`example`).addEventListener(`click`,()=>{e.value=`hello-42`,s(),e.focus()})}if(a===`clear-type`){let e=d(`clear-input`),t=d(`clear`),n=d(`copy`),r=d(`font-size`),i=()=>{t.disabled=!e.value,n.disabled=!e.value};e.addEventListener(`input`,i),t.addEventListener(`click`,()=>{e.value=``,i(),e.focus()}),n.addEventListener(`click`,()=>{m(e.value)}),r.addEventListener(`input`,()=>{e.style.fontSize=`${r.value}px`,d(`size-value`).textContent=`${r.value} px`}),document.fonts.load(`32px "Atkinson Hyperlegible Mono"`).then(e=>{e.length||(d(`font-status`).hidden=!1)}).catch(()=>{d(`font-status`).hidden=!1})}