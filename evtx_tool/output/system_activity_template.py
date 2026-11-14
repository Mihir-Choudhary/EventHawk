"""The page for evtx_tool.output.system_activity_report (kept apart so the
report logic stays readable).  Placeholders: __TITLE__, __LOGO__ (head) and
__DATA__ (the JSON payload; filled last, see render_html)."""

_LIGHT = """
  --bg:#f6f2ea; --surface:#fffcf7; --surface-2:#efe9de; --surface-3:#e6ddcd;
  --line:#e3dacb; --line-2:#cdc2ae; --line-input:#938464; --text:#1e1a14; --text-2:#5a4e42; --text-3:#6e6253;
  --accent:#7a5c1e; --accent-soft:#f1e6cc; --sel:#f3e7c9; --hover:#f4eee4; --ring:rgba(122,92,30,.45);
  --warn:#8a4800; --shadow:0 18px 40px -16px rgba(60,45,20,.30),0 2px 6px rgba(60,45,20,.08);
  --st-on:#3f8f55; --st-sleep:#7d9fd0; --st-hib:#a08ccd; --st-low:#8fb5c2; --st-ms:#b3cad1; --st-off:#c9c0b2;
  --st-crash:#c25b49; --st-lock:#d4a03e; --st-scr-on:#d8b24a; --st-scr-off:#9aa1ab; --st-other:#d3cabb;
  --heat-0:#ece5d8; --tick:#7a5c1e; --grid:rgba(90,78,66,.09); color-scheme:light;"""

_DARK = """
  --bg:#121417; --surface:#191c20; --surface-2:#20242a; --surface-3:#2a2f36;
  --line:#2a2f36; --line-2:#3a414a; --line-input:#7a7468; --text:#e8e4dc; --text-2:#aaa397; --text-3:#a39d91;
  --accent:#d8b36a; --accent-soft:#3b3222; --sel:#2f2a1f; --hover:#1f2328; --ring:rgba(216,179,106,.5);
  --warn:#f0a65a; --shadow:0 18px 44px -14px rgba(0,0,0,.65),0 2px 8px rgba(0,0,0,.4);
  --st-on:#58b56f; --st-sleep:#5f7fae; --st-hib:#8a77b8; --st-low:#4d7f8f; --st-ms:#4a6670; --st-off:#4a4640;
  --st-crash:#e0705b; --st-lock:#d9a441; --st-scr-on:#cfae4f; --st-scr-off:#5d6570; --st-other:#4a463f;
  --heat-0:#22262c; --tick:#d8b36a; --grid:rgba(232,228,220,.07); color-scheme:dark;"""

_CSS = r"""
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-padding-top:76px}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;font-variant-numeric:tabular-nums}
:root{--mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace}
::selection{background:var(--accent-soft);color:var(--text)}
a{color:var(--accent);text-underline-offset:3px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
*{scrollbar-color:var(--line-2) transparent;scrollbar-width:thin}
svg.i{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round;flex:none}
.wrap{width:min(1440px,100% - 32px);margin:0 auto}
button{font:inherit;color:inherit}
/* bar */
.bar{position:sticky;top:0;z-index:30;background:color-mix(in srgb,var(--bg) 90%,transparent);backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--line)}
.bar .wrap{display:flex;align-items:center;gap:14px;min-height:58px}
.brand{display:flex;align-items:center;gap:9px;font-weight:650;letter-spacing:-.01em;white-space:nowrap}
.brand img{height:26px;width:auto;display:block}
.nav{display:flex;gap:2px;overflow-x:auto;flex:1;min-width:0}
.nav a{color:var(--text-2);text-decoration:none;padding:6px 10px;border-radius:7px;white-space:nowrap;font-size:13.5px}
.nav a:hover{background:var(--hover);color:var(--text)}
.nav a.on{color:var(--text);background:var(--surface-2)}
.nav a .n{color:var(--text-3);margin-left:5px;font-size:12px}
.tools{display:flex;gap:6px;align-items:center}
.chip{display:none;align-items:center;gap:6px;height:30px;padding:0 4px 0 11px;border-radius:15px;background:var(--accent-soft);color:var(--text);font-size:12.5px;white-space:nowrap;border:1px solid color-mix(in srgb,var(--accent) 30%,transparent)}
.chip.on{display:inline-flex}
.chip button{all:unset;cursor:pointer;width:22px;height:22px;border-radius:11px;display:grid;place-items:center}
.chip button:hover{background:color-mix(in srgb,var(--accent) 18%,transparent)}
.chip svg{width:13px;height:13px}
.btn{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 11px;border:1px solid var(--line-input);background:var(--surface);border-radius:8px;font-size:13px;cursor:pointer;white-space:nowrap}
.btn:hover{background:var(--hover)}
.btn.icon{width:32px;justify-content:center;padding:0}
.btn.ghost{border-color:transparent;background:transparent}
.btn.ghost:hover{background:var(--hover)}
select,input[type=datetime-local]{height:32px;border:1px solid var(--line-input);background:var(--surface);color:var(--text);border-radius:8px;font:inherit;font-size:13px;padding:0 8px}
select{max-width:240px}
input[type=datetime-local]{font-family:var(--mono);font-size:12.5px}
input[type=datetime-local]::-webkit-calendar-picker-indicator{opacity:.6;cursor:pointer}
/* layout */
main{padding:30px 0 90px}
section{margin:0 0 56px}
h1{font-size:30px;line-height:1.12;letter-spacing:-.025em;margin:0 0 10px;font-weight:680;text-wrap:balance}
h2{font-size:20px;letter-spacing:-.015em;margin:0 0 4px;font-weight:640}
.lede{color:var(--text-2);margin:0 0 18px;max-width:78ch;font-size:14.5px}
.lede b{color:var(--text);font-weight:600}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.ph{display:flex;align-items:baseline;gap:12px;padding:14px 18px 0}
.ph h3{margin:0;font-size:14px;font-weight:620}
.ph .sub{color:var(--text-3);font-size:12.5px}
.facts{display:flex;flex-wrap:wrap;gap:8px 32px;margin:0 0 22px;padding:0}
.facts div{display:flex;flex-direction:column}
.facts dt{font-size:12px;color:var(--text-3)}
.facts dd{margin:0;font-size:16px;font-weight:620}
.facts dd small{font-weight:400;color:var(--text-2);font-size:13px}
/* range */
.range{padding:16px 18px 16px;margin:0 0 18px}
.range-top{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;margin:0 0 12px}
.range-top .lbl{font-size:13px;font-weight:620}
.range-top .when{font-size:13px;color:var(--text-2)}
.range-top .when b{color:var(--text);font-weight:600}
.range-ctl{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-left:auto}
.range-ctl label{font-size:12.5px;color:var(--text-3);display:inline-flex;align-items:center;gap:6px}
.seg{display:inline-flex;border:1px solid var(--line-input);border-radius:8px;overflow:hidden;background:var(--surface)}
.seg button{border:0;background:transparent;color:var(--text-2);font-size:12.5px;padding:0 10px;height:30px;cursor:pointer;white-space:nowrap}
.seg button+button{border-left:1px solid var(--line-2)}
.seg button:hover{background:var(--hover);color:var(--text)}
.seg button[aria-pressed=true]{background:var(--accent-soft);color:var(--text)}
.brush{position:relative;height:74px;user-select:none;touch-action:none}
.brush svg{position:absolute;left:0;top:0;width:100%;height:52px;display:block}
.brush .b-on{fill:var(--st-on)}
.brush .b-sl{fill:var(--st-sleep);opacity:.22}
.brush .b-ev{fill:var(--line-2)}
.brush .base{position:absolute;left:0;right:0;top:52px;height:1px;background:var(--line-2)}
.brush .months{position:absolute;left:0;right:0;top:56px;height:16px;font-size:11px;color:var(--text-3)}
.brush .months span{position:absolute;white-space:nowrap;padding-left:4px;border-left:1px solid var(--line-2);height:16px;line-height:16px}
.brush .dim{position:absolute;top:0;height:52px;background:color-mix(in srgb,var(--bg) 70%,transparent);pointer-events:none}
.brush .sel{position:absolute;top:0;height:52px;border:1.5px solid var(--accent);border-radius:4px;pointer-events:none;box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 14%,transparent)}
.brush .sel::before,.brush .sel::after{content:"";position:absolute;top:14px;width:6px;height:22px;border-radius:3px;background:var(--accent)}
.brush .sel::before{left:-4px}.brush .sel::after{right:-4px}
.brush.full .sel{opacity:0}
.brush .hit{position:absolute;inset:0 0 22px 0;cursor:crosshair;border-radius:4px}
.brush .hit.edge{cursor:ew-resize}
.brush .hit:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.hint{font-size:12px;color:var(--text-3);margin:6px 0 0}
/* overview grid */
.ov{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,1fr);gap:18px;align-items:start}
.cards{display:grid;gap:18px}
.layer{padding:0 0 12px}
.stack{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--surface-2);margin:12px 18px 10px;gap:2px}
.stack i{display:block;min-width:2px}
.stack i.unp{background:repeating-linear-gradient(135deg,var(--st-low) 0 4px,transparent 4px 7px)}
.stack i.none{background:repeating-linear-gradient(135deg,var(--surface-3) 0 4px,transparent 4px 7px)}
.ltab{width:calc(100% - 36px);margin:0 18px;border-collapse:collapse;font-size:13px}
.ltab td{padding:5px 0;border-top:1px solid var(--line)}
.ltab tr:first-child td{border-top:0}
.ltab td.num{text-align:right;white-space:nowrap;padding-left:14px}
.ltab td.dim{color:var(--text-2)}
.ltab tr.none td{color:var(--text-3)}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:8px;vertical-align:-1px;flex:none}
.sw.unp{background:repeating-linear-gradient(135deg,var(--st-low) 0 2px,transparent 2px 4px);outline:1px solid var(--st-low);outline-offset:-1px}
.sw.none{background:repeating-linear-gradient(135deg,var(--line-2) 0 2px,transparent 2px 4px);outline:1px solid var(--line-2);outline-offset:-1px}
/* calendar */
.cal{padding:0 18px 16px}
.cal-wrap{display:flex;flex-wrap:wrap;gap:18px 22px;margin-top:14px}
.cal-m{width:max-content}
.cal-t{font-size:12px;font-weight:600;color:var(--text-2);margin:0 0 6px}
.cal-g{display:grid;grid-template-columns:repeat(7,24px);gap:3px}
.cal-g .wd{font-size:10.5px;color:var(--text-3);text-align:center;line-height:14px}
.cal-g button{all:unset;width:24px;height:24px;border-radius:4px;background:var(--heat-0);cursor:pointer;box-sizing:border-box}
.cal-g button.nd{background:transparent;box-shadow:inset 0 0 0 1px var(--line);cursor:default}
.cal-g button:hover{box-shadow:inset 0 0 0 2px var(--text)}
.cal-g button.in{box-shadow:0 0 0 2px var(--accent)}
.cal-g button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.l1{background:color-mix(in srgb,var(--st-on) 22%,var(--heat-0))!important}
.l2{background:color-mix(in srgb,var(--st-on) 42%,var(--heat-0))!important}
.l3{background:color-mix(in srgb,var(--st-on) 62%,var(--heat-0))!important}
.l4{background:color-mix(in srgb,var(--st-on) 82%,var(--heat-0))!important}
.l5{background:var(--st-on)!important}
.scale{display:flex;align-items:center;gap:4px;font-size:11.5px;color:var(--text-3);margin-top:14px}
.scale i{width:12px;height:12px;border-radius:3px;background:var(--heat-0);display:inline-block}
/* hour heat */
.heat{padding:0 18px 16px;overflow-x:auto}
.hgrid{display:grid;grid-template-columns:38px repeat(24,minmax(18px,1fr));gap:3px;margin-top:14px;min-width:560px}
.hgrid .hl{font-size:10.5px;color:var(--text-3);text-align:left}
.hgrid .dl{font-size:11.5px;color:var(--text-2);line-height:20px}
.hgrid i{display:block;height:20px;border-radius:4px;background:var(--heat-0)}
.hgrid i:hover{box-shadow:inset 0 0 0 2px var(--text)}
.notes{display:grid;gap:8px;margin-top:18px}
.note{display:flex;gap:10px;align-items:flex-start;color:var(--text-2);font-size:13px;max-width:110ch}
.note svg{margin-top:2px;color:var(--text-3)}
.note.warn{color:var(--warn)}.note.warn svg{color:var(--warn)}
/* state colours */
.st-on{background:var(--st-on)}.st-sleep{background:var(--st-sleep)}.st-hib{background:var(--st-hib)}.st-low{background:var(--st-low)}
.st-ms{background:var(--st-ms)}.st-off{background:var(--st-off)}.st-crash{background:var(--st-crash)}.st-lock{background:var(--st-lock)}
.st-scr-on{background:var(--st-scr-on)}.st-scr-off{background:var(--st-scr-off)}.st-other{background:var(--st-other)}
/* filters */
.ctrl{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin:0 0 12px}
.acts{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px}
.act{display:inline-flex;align-items:center;gap:7px;height:28px;padding:0 10px;border-radius:14px;border:1px solid var(--line-input);background:var(--surface);font-size:12.5px;cursor:pointer;color:var(--text)}
.act .sw{margin:0}
.act .c{color:var(--text-3);font-size:11.5px}
.act[aria-pressed=false]{color:var(--text-3);background:transparent;border-style:dashed}
.act[aria-pressed=false] .sw{opacity:.3}
.act:hover{border-color:var(--text-3)}
.acts .reset{all:unset;cursor:pointer;font-size:12.5px;color:var(--accent);padding:0 6px;height:28px;line-height:28px}
.search{position:relative;flex:1 1 280px;max-width:460px}
.search svg{position:absolute;left:10px;top:9px;color:var(--text-3);pointer-events:none}
.search input{width:100%;height:34px;border:1px solid var(--line-input);background:var(--surface);color:var(--text);border-radius:9px;font:inherit;font-size:13.5px;padding:0 40px 0 32px}
.search input::placeholder{color:var(--text-3)}
.search kbd{position:absolute;right:8px;top:8px;font:11px var(--mono);color:var(--text-3);border:1px solid var(--line-2);border-radius:4px;padding:0 5px;background:var(--surface-2)}
.chk{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--text-2);cursor:pointer;user-select:none;white-space:nowrap}
.chk input{accent-color:var(--accent);width:15px;height:15px;margin:0}
.count{font-size:13px;color:var(--text-2);margin-left:auto;white-space:nowrap}
.count b{color:var(--text);font-weight:620}
.dd{position:relative}
.dd>summary{list-style:none}
.dd>summary::-webkit-details-marker{display:none}
.dd>summary .btn{pointer-events:none}
.dd-pop{position:absolute;z-index:25;top:38px;left:0;min-width:270px;background:var(--surface);border:1px solid var(--line-2);border-radius:10px;box-shadow:var(--shadow);padding:6px}
.dd-pop label{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:6px;font-size:13px;cursor:pointer}
.dd-pop label:hover{background:var(--hover)}
.dd-pop label .c{margin-left:auto;color:var(--text-3);font-size:12px}
.dd-pop label .only{all:unset;font-size:11.5px;color:var(--accent);padding:2px 6px;opacity:0;cursor:pointer;border-radius:4px}
.dd-pop label:hover .only,.dd-pop label:focus-within .only{opacity:1}
.dd-pop label .only:focus-visible{opacity:1;outline:2px solid var(--accent)}
.dd-pop .ft{display:flex;gap:8px;border-top:1px solid var(--line);margin-top:4px;padding:6px 4px 2px}
.dd-pop .ft button{all:unset;cursor:pointer;font-size:12.5px;color:var(--accent);padding:2px 4px}
/* timeline */
.tl{position:relative}
.tl-axis,.day{display:grid;grid-template-columns:132px minmax(420px,1fr) 92px;align-items:center;column-gap:14px;padding:0 16px}
.tl-axis{position:sticky;top:var(--bar-h,58px);z-index:3;background:var(--surface);border-bottom:1px solid var(--line);height:34px;font-size:11.5px;color:var(--text-3);border-radius:12px 12px 0 0}
.tl-axis .hours{position:relative;height:100%}
.tl-axis .hours span{position:absolute;top:9px;transform:translateX(-50%)}
.tl-axis .hours span:first-child{transform:none}.tl-axis .hours span:last-child{transform:translateX(-100%)}
.day{min-height:40px;border-bottom:1px solid var(--line);content-visibility:auto;contain-intrinsic-size:auto 40px}
.day:last-child{border-bottom:0}
.day:hover{background:var(--hover)}
.day.we .dl{color:var(--text-3)}
.dl{font-size:12.5px;color:var(--text-2);white-space:nowrap}
.dl b{color:var(--text);font-weight:600;margin-left:6px}
.track{position:relative;height:26px;margin:7px 0;border-radius:5px;background:repeating-linear-gradient(135deg,transparent 0 5px,var(--grid) 5px 6px)}
.track .gl{position:absolute;top:-3px;bottom:-3px;width:1px;background:var(--grid)}
.track i{position:absolute;display:block;min-width:2px;cursor:pointer}
.track .lp{top:0;height:18px;border-radius:4px}
.track .lp.soft{opacity:.55;height:18px}
.track .lp.st-off{opacity:1;background:var(--surface-3)}
.track .ls{top:21px;height:4px;border-radius:2px}
.track .ll{top:21px;height:4px;border-radius:2px}
.track .tk{top:-2px;height:22px;width:2px;background:var(--tick);opacity:.7;border-radius:1px}
.track .clk{top:-4px;height:30px;width:2px;background:var(--st-crash);border-radius:1px;z-index:1}
.track .clk.wake{background:var(--text-3);opacity:.55;width:1px}
.track .edge{top:0;height:18px;width:2px;background:repeating-linear-gradient(var(--text-2) 0 3px,transparent 3px 5px)}
.track.two{height:26px}
.track:not(.two) .lp{height:26px;top:0}
.track i:hover{outline:2px solid var(--text);outline-offset:1px;z-index:1}
.track i.sel{outline:2px solid var(--accent);outline-offset:1px;z-index:2;opacity:1}
.dsum{font-size:12.5px;color:var(--text-2);text-align:right;white-space:nowrap}
.dsum b{color:var(--text);font-weight:600}
.gap{padding:7px 16px 7px 162px;font-size:12px;color:var(--text-3);border-bottom:1px solid var(--line)}
.more{display:flex;justify-content:center;padding:12px;border-top:1px solid var(--line)}
.tl-empty{padding:28px 16px;text-align:center;color:var(--text-2)}
#tip{position:fixed;z-index:60;pointer-events:none;background:var(--text);color:var(--bg);font-size:12.5px;line-height:1.45;padding:8px 11px;border-radius:8px;max-width:360px;box-shadow:var(--shadow);opacity:0;transition:opacity .08s}
#tip.on{opacity:1}
#tip b{font-weight:620}
#tip .m{font-family:var(--mono);font-size:11.5px;opacity:.85}
/* virtual tables */
.vt{overflow:auto;position:relative;height:min(66vh,var(--h,480px));min-height:190px;outline:none}
.vt .th,.vt .tr{display:grid;grid-template-columns:var(--cols);min-width:var(--minw,900px);column-gap:14px;padding:0 16px}
.vt .th{position:sticky;top:0;z-index:2;background:var(--surface);border-bottom:1px solid var(--line-2);height:38px;align-items:center;font-size:12.5px;color:var(--text-2);font-weight:600}
.vt .th button{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:4px;border-radius:4px}
.vt .th button:hover{color:var(--text)}
.vt .th button:focus-visible{outline:2px solid var(--accent)}
.vt .th svg{width:12px;height:12px;opacity:0}
.vt .th [aria-sort=ascending] svg,.vt .th [aria-sort=descending] svg{opacity:1}
.vt .th [aria-sort=ascending] svg{transform:rotate(180deg)}
.vt .body{position:relative}
.vt .tr{position:absolute;left:0;right:0;height:34px;align-items:center;font-size:13px;border-bottom:1px solid var(--line);cursor:pointer;contain:layout style}
.vt .tr:hover{background:var(--hover)}
.vt .tr.sel{background:var(--sel)}
.vt .tr.dup{color:var(--text-3)}
.td{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.td.m{font-family:var(--mono);font-size:12px}
.td.r{text-align:right}
.td.dim{color:var(--text-2)}
.pill{display:inline-flex;align-items:center;max-width:100%;gap:0}
.pill span{overflow:hidden;text-overflow:ellipsis}
.pill .code{color:var(--text-3);font-size:11.5px;margin-left:6px}
mark{background:var(--accent-soft);color:inherit;border-radius:2px;padding:0 1px}
.empty{position:absolute;left:0;right:0;top:58px;text-align:center;color:var(--text-2);font-size:13.5px;padding:0 16px}
.empty .btn{margin-top:10px}
/* inspector */
#insp{position:fixed;top:0;right:0;bottom:0;width:min(580px,100%);z-index:50;background:var(--surface);border-left:1px solid var(--line);box-shadow:var(--shadow);transform:translateX(102%);transition:transform .24s cubic-bezier(.16,1,.3,1),visibility 0s .24s;display:flex;flex-direction:column;visibility:hidden}
#insp.on{transform:none;visibility:visible;transition:transform .24s cubic-bezier(.16,1,.3,1)}
#insp header{display:flex;align-items:flex-start;gap:10px;padding:18px 18px 14px;border-bottom:1px solid var(--line)}
#insp header h2{font-size:18px;margin:0;line-height:1.3;overflow-wrap:anywhere;display:flex;align-items:center;gap:8px}
#insp header p{margin:3px 0 0;color:var(--text-2);font-size:13px}
#insp header .x{margin-left:auto}
#insp .scroll{overflow:auto;padding:6px 18px 36px;flex:1}
#insp h3{font-size:12.5px;font-weight:620;color:var(--text-2);margin:22px 0 8px}
.kv{display:grid;grid-template-columns:minmax(96px,max-content) 1fr;gap:6px 16px;margin:0;font-size:13px}
.kv dt{color:var(--text-2)}
.kv dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}
.kv dd.m{font-family:var(--mono);font-size:12.5px}
.kv .mean{font-family:inherit;font-size:12.5px;color:var(--text-2);margin-left:10px;white-space:normal}
.big{display:flex;gap:22px;flex-wrap:wrap;margin:14px 0 4px}
.big div{display:flex;flex-direction:column}
.big span{font-size:12px;color:var(--text-3)}
.big b{font-family:var(--mono);font-size:13px;font-weight:500}
.how{font-size:13px;color:var(--text-2);background:var(--surface-2);border-radius:8px;padding:9px 12px;margin:12px 0 14px;max-width:70ch}
.evc{border:1px solid var(--line);border-radius:10px;margin:10px 0 14px;overflow:hidden}
.evc>.hd{display:flex;align-items:center;gap:8px;padding:9px 10px 9px 12px;background:var(--surface-2);font-size:13px}
.evc>.hd b{font-weight:620}
.evc>.hd .t{font-family:var(--mono);font-size:12px;color:var(--text-2)}
.evc>.hd .sp{margin-left:auto;display:flex;gap:2px}
.evc .bd{padding:10px 12px 12px}
.evc .role{font-size:12px;color:var(--text-3);margin-bottom:6px}
.evc .desc{margin:0 0 10px;font-size:13px;max-width:70ch}
.evc .sub{font-size:12px;color:var(--text-3);margin:0 0 6px}
details.sys>summary{cursor:pointer;color:var(--text-2);font-size:12.5px;margin:10px 0 6px;list-style:none;display:flex;align-items:center;gap:6px}
details.sys>summary::-webkit-details-marker{display:none}
details.sys>summary svg{width:13px;height:13px;transition:transform .15s}
details.sys[open]>summary svg{transform:rotate(90deg)}
.used a{display:flex;align-items:center;padding:4px 0}
.dupnote{font-size:12.5px;color:var(--text-2);margin:6px 0 0}
.skip{position:absolute;left:12px;top:-60px;z-index:100;background:var(--text);color:var(--bg);padding:8px 12px;border-radius:8px;text-decoration:none}
.skip:focus{top:10px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.toast{position:fixed;bottom:22px;left:50%;transform:translate(-50%,20px);background:var(--text);color:var(--bg);padding:8px 14px;border-radius:8px;font-size:13px;opacity:0;transition:.18s;z-index:70;pointer-events:none}
.toast.on{opacity:1;transform:translate(-50%,0)}
footer{color:var(--text-3);font-size:12px;border-top:1px solid var(--line);padding:18px 0 40px}
@media (max-width:1100px){.ov{grid-template-columns:1fr}}
@media (max-width:760px){
  .bar .wrap{flex-wrap:wrap;gap:8px;padding:8px 0}
  .nav{order:3;flex-basis:100%}
  h1{font-size:24px}
  .range-ctl{margin-left:0}
  .tl-axis,.day{grid-template-columns:62px minmax(0,1fr) 0;column-gap:8px;padding:0 10px}
  .dl .y,.tl-axis>span:last-child{display:none}
  .dl b{margin-left:4px}
  .tl-axis .hours span{font-size:10.5px}
  .dsum{display:none}
  .gap{padding-left:102px}
  .count{margin-left:0}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media print{
  :root{--bg:#fff;--surface:#fff;color-scheme:light}
  .bar,#insp,#tip,.ctrl,.acts,.toast,.noprint,.more{display:none!important}
  .vt{max-height:none!important;height:auto!important;overflow:visible!important}
  .vt .tr{position:static!important;transform:none!important;break-inside:avoid}
  .tl-axis{position:static}
  .day{content-visibility:visible;break-inside:avoid}
}
"""

_BODY = r"""
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
 <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></symbol>
 <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
 <symbol id="i-moon" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></symbol>
 <symbol id="i-print" viewBox="0 0 24 24"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></symbol>
 <symbol id="i-x" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></symbol>
 <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
 <symbol id="i-down" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></symbol>
 <symbol id="i-right" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></symbol>
 <symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></symbol>
 <symbol id="i-alert" viewBox="0 0 24 24"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></symbol>
 <symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></symbol>
 <symbol id="i-cal" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></symbol>
 <symbol id="i-filter" viewBox="0 0 24 24"><path d="M22 3H2l8 9.5V19l4 2v-8.5z"/></symbol>
</svg>
<a class="skip" href="#overview">Skip to the report</a>
<header class="bar">
 <div class="wrap">
  <div class="brand"><img src="__LOGO__" alt="" width="33" height="26">EventHawk</div>
  <nav class="nav" aria-label="Sections">
   <a href="#overview">Overview</a>
   <a href="#timeline">Day by day</a>
   <a href="#periods">Periods<span class="n" id="n-periods"></span></a>
   <a href="#moments">Moments<span class="n" id="n-moments"></span></a>
   <a href="#events">Raw events<span class="n" id="n-events"></span></a>
  </nav>
  <div class="tools">
   <span class="chip" id="chip"><svg class="i"><use href="#i-cal"/></svg><span id="chip-t"></span><button type="button" id="chip-x" aria-label="Show the whole log" title="Show the whole log"><svg class="i"><use href="#i-x"/></svg></button></span>
   <select id="host" aria-label="Computer"></select>
   <button class="btn icon ghost" id="theme" type="button" aria-label="Switch to dark theme" title="Switch theme"><svg class="i"><use href="#i-moon"/></svg></button>
   <button class="btn icon ghost" id="print" type="button" aria-label="Print" title="Print or save as PDF"><svg class="i"><use href="#i-print"/></svg></button>
  </div>
 </div>
</header>
<main class="wrap" id="main">
 <section id="overview" aria-labelledby="h-ov">
  <h1 id="h-ov">System activity</h1>
  <p class="lede" id="ov-lede"></p>
  <dl class="facts" id="facts"></dl>

  <div class="panel range noprint" aria-labelledby="range-l">
   <div class="range-top">
    <span class="lbl" id="range-l">Time range</span>
    <span class="when" id="range-when"></span>
    <div class="range-ctl">
     <div class="seg" role="group" aria-label="Quick ranges" id="presets">
      <button type="button" data-preset="all">Whole log</button><button type="button" data-preset="1">Last day</button><button type="button" data-preset="7">7 days</button><button type="button" data-preset="30">30 days</button>
     </div>
     <label>From <input type="datetime-local" id="r-from" step="60" aria-label="From (UTC)"></label>
     <label>To <input type="datetime-local" id="r-to" step="60" aria-label="To (UTC)"> UTC</label>
    </div>
   </div>
   <div class="brush" id="brush">
    <svg preserveAspectRatio="none" aria-hidden="true"></svg>
    <div class="base"></div><div class="months"></div>
    <div class="dim" id="dim-l"></div><div class="dim" id="dim-r"></div><div class="sel" id="b-sel"></div>
    <div class="hit" id="b-hit" tabindex="0" role="slider" aria-label="Time range: drag to select days, arrow keys move it"></div>
   </div>
   <p class="hint">Drag across the strip to pick days, drag an edge to resize, double-click for the whole log. Bars show hours on (green) and asleep (blue) per day.</p>
  </div>

  <div class="ov">
   <div class="cards" id="layers"></div>
   <div class="cards">
    <div class="panel"><div class="ph"><h3>Calendar</h3><span class="sub">hours on per day · click a day, shift-click for a span</span></div><div class="cal"><div class="cal-wrap" id="cal"></div>
     <div class="scale"><span>Less</span><i></i><i class="l1"></i><i class="l2"></i><i class="l3"></i><i class="l4"></i><i class="l5"></i><span>More</span><span style="margin-left:12px"><i style="background:transparent;box-shadow:inset 0 0 0 1px var(--line);vertical-align:-2px"></i> no records</span></div></div></div>
   </div>
  </div>
  <div class="panel" style="margin-top:18px"><div class="ph"><h3>Usual hours</h3><span class="sub">share of each hour the computer was on, by weekday (UTC) · <span id="heat-max"></span></span></div><div class="heat"><div class="hgrid" id="heat"></div></div></div>
  <div class="notes" id="ov-notes"></div>
 </section>

 <section id="timeline" aria-labelledby="h-tl">
  <h2 id="h-tl">Day by day</h2>
  <p class="lede">One row per UTC day of the time range. Green is on; tinted is asleep or in low power; blank is shut down or not recorded. Click a bar for its events.</p>
  <div class="ctrl noprint">
   <div class="seg" role="group" aria-label="Lanes" id="lanes">
    <button type="button" data-lane="Screen" aria-pressed="false">Screen</button><button type="button" data-lane="Lock" aria-pressed="false">Lock</button><button type="button" data-lane="Moments" aria-pressed="false">Moments</button>
   </div>
   <label class="chk"><input type="checkbox" id="tl-short" checked> Hide periods under 1 s</label>
  </div>
  <div class="acts" id="acts" role="group" aria-label="Activities shown"></div>
  <p class="sr">The same periods are in the Periods table below, which works with the keyboard.</p>
  <div class="panel tl" id="tl" role="img" aria-label="Day-by-day timeline of power, screen and lock periods; the Periods table below lists the same periods."></div>
 </section>

 <section id="periods" aria-labelledby="h-p">
  <h2 id="h-p">Periods</h2>
  <p class="lede">Every period in the time range. Click a row to see it in full with the events that start and end it.</p>
  <div class="ctrl">
   <label class="search"><svg class="i"><use href="#i-search"/></svg><input type="search" id="q-periods" placeholder="Search activity, evidence, notes, times" aria-label="Search periods" autocomplete="off" spellcheck="false"><kbd>/</kbd></label>
   <details class="dd" id="dd-acts"><summary><span class="btn"><svg class="i"><use href="#i-filter"/></svg><span id="dd-acts-l">Activities</span><svg class="i" style="width:13px;height:13px"><use href="#i-down"/></svg></span></summary><div class="dd-pop" id="dd-acts-pop"></div></details>
   <label class="chk"><input type="checkbox" id="p-short" checked> <span id="p-short-l">Hide periods under 1 s</span></label>
   <span class="count" id="c-periods" aria-live="polite"></span>
  </div>
  <div class="panel vt" id="t-periods" tabindex="0" role="grid" aria-label="Periods"></div>
 </section>

 <section id="moments" aria-labelledby="h-m">
  <h2 id="h-m">Moments</h2>
  <p class="lede">Single events worth knowing in the time range: boots, clock changes, power source, logon notifications.</p>
  <div class="ctrl">
   <label class="search"><svg class="i"><use href="#i-search"/></svg><input type="search" id="q-moments" placeholder="Search what happened, details, evidence" aria-label="Search moments" autocomplete="off" spellcheck="false"><kbd>/</kbd></label>
   <select id="m-kind" aria-label="Kind of moment"></select>
   <span class="count" id="c-moments" aria-live="polite"></span>
  </div>
  <div class="panel vt" id="t-moments" tabindex="0" role="grid" aria-label="Moments"></div>
 </section>

 <section id="events" aria-labelledby="h-e">
  <h2 id="h-e">Raw events</h2>
  <p class="lede">Every event the analysis read in the time range, with all of its fields. Search looks in every field value, not just the columns.</p>
  <div class="ctrl">
   <label class="search"><svg class="i"><use href="#i-search"/></svg><input type="search" id="q-events" placeholder="Search any field: 566, Kernel-Power, S-1-5-18, a record number" aria-label="Search raw events" autocomplete="off" spellcheck="false"><kbd>/</kbd></label>
   <select id="e-kind" aria-label="Event type"></select>
   <label class="chk" id="e-dups-w" hidden><input type="checkbox" id="e-dups"> <span id="e-dups-l">Show copies</span></label>
   <span class="count" id="c-events" aria-live="polite"></span>
  </div>
  <div class="panel vt" id="t-events" tabindex="0" role="grid" aria-label="Raw events"></div>
 </section>
 <footer id="foot"></footer>
</main>
<aside id="insp" role="dialog" aria-label="Details" aria-hidden="true">
 <header><div id="insp-head"></div><button class="btn icon ghost x" id="insp-x" type="button" aria-label="Close details" title="Close (Esc)"><svg class="i"><use href="#i-x"/></svg></button></header>
 <div class="scroll" id="insp-body"></div>
</aside>
<div id="tip" role="tooltip"></div>
<div class="toast" id="toast" role="status"></div>
"""

_JS = r"""
(() => {
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const $ = id => document.getElementById(id);
const ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"};
const h = s => s == null ? "" : String(s).replace(/[&<>"']/g, c => ESC[c]);
const fmtN = n => Number(n).toLocaleString("en-US");
const icon = n => `<svg class="i"><use href="#i-${n}"/></svg>`;
const pad = n => String(n).padStart(2, "0");
const DAY = 86400e6, HOUR = 3600e6, SHORT = D.meta.short_us;
const P = D.periods, M = D.moments, E = D.events;
const multi = D.hosts.length > 1;
let hostSel = D.hosts.length === 1 ? 0 : -1;
const hostName = i => D.hosts[i] ? D.hosts[i] : "(no computer name)";
const hostOk = i => hostSel < 0 || i === hostSel;
const MON = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const WEEK = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
const isoOf = us => new Date(us / 1000).toISOString();
const fmtDT = us => isoOf(us).slice(0, 16).replace("T", " ");
const niceDay = us => { const d = new Date(us / 1000); return `${d.getUTCDate()} ${MON[d.getUTCMonth()]} ${d.getUTCFullYear()}`; };
const niceDT = us => { const d = new Date(us / 1000); return `${d.getUTCDate()} ${MON[d.getUTCMonth()]} ${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; };
function fmtTotal(us){
  const s = us / 1e6;
  if (s < 60) return s < 10 ? s.toFixed(1) + " s" : Math.floor(s) + " s";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} m ${pad(Math.floor(s % 60))} s`;
  return `${Math.floor(m / 60)} h ${pad(m % 60)} m`;
}
function fmtExact(us){
  us = Math.round(us);
  const whole = Math.floor(us / 1e6), fr = us - whole * 1e6;
  const hh = Math.floor(whole / 3600), mm = Math.floor(whole % 3600 / 60), ss = whole % 60;
  const f = fr ? ("." + String(fr).padStart(6, "0")).replace(/0+$/, "") : "";
  return hh ? `${hh}h ${pad(mm)}m ${pad(ss)}${f}s` : mm ? `${mm}m ${pad(ss)}${f}s` : `${ss}${f}s`;
}

// ── states ───────────────────────────────────────────────────────
const base = s => s.split(" (")[0];
const ST = {"On":"on","Sleep":"sleep","Hibernate":"hib","Sleep or hibernate":"sleep","Modern Standby":"ms","Shut down":"off",
  "Off":"off","Off (unexpected shutdown)":"crash","Locked":"lock","Screen saver":"lock","Screen on":"scr-on","Screen off":"scr-off","Low power":"low"};
const stCache = {};
const stKey = s => stCache[s] || (stCache[s] = ST[s] || ST[base(s)] || (s.indexOf("unexpected") >= 0 ? "crash" : "other"));
const rank = {}; D.order.forEach((s, i) => rank[s] = i);
function kindOf(p){
  const b = base(p[2]);
  if (p[1] === "Screen") return b === "Screen on" ? "scr" : null;
  if (p[1] !== "Power") return null;
  if (b === "On") return "on";
  const k = stKey(p[2]);
  return k === "off" || k === "crash" ? "off" : "sleep";
}

// ── theme, toast, copy ───────────────────────────────────────────
const root = document.documentElement;
function store(k, v){ try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch(e){ return null; } }
const isDark = () => { const t = root.getAttribute("data-theme"); return t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches; };
function syncThemeBtn(){ const d = isDark(), b = $("theme"); b.innerHTML = icon(d ? "sun" : "moon"); b.setAttribute("aria-label", d ? "Switch to light theme" : "Switch to dark theme"); }
const savedTheme = store("eh-theme"); if (savedTheme === "dark" || savedTheme === "light") root.setAttribute("data-theme", savedTheme);
$("theme").addEventListener("click", () => { const t = isDark() ? "light" : "dark"; root.setAttribute("data-theme", t); store("eh-theme", t); syncThemeBtn(); });
syncThemeBtn();
let toastT;
function toast(msg){ const t = $("toast"); t.textContent = msg; t.classList.add("on"); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("on"), 1600); }
function copy(text){
  const fallback = () => { const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); toast("Copied"); } catch(e){ toast("Copy is blocked here: select the text instead"); } ta.remove(); };
  if (navigator.clipboard && window.isSecureContext !== false) navigator.clipboard.writeText(text).then(() => toast("Copied"), fallback); else fallback();
}
const tip = $("tip");
function tipShow(html, ev){ tip.innerHTML = html; tip.classList.add("on"); tipMove(ev); }
function tipMove(ev){
  if (!tip.classList.contains("on")) return;
  let x = ev.clientX + 14, y = ev.clientY + 16; const w = tip.offsetWidth, hh = tip.offsetHeight;
  if (x + w > innerWidth - 8) x = ev.clientX - w - 14;
  if (y + hh > innerHeight - 8) y = ev.clientY - hh - 12;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const tipHide = () => tip.classList.remove("on");

// ── range ────────────────────────────────────────────────────────
const T0 = D.meta.first_us, T1 = D.meta.last_us;
const FA = T0 == null ? 0 : Math.floor(T0 / DAY) * DAY, FB = T1 == null ? DAY : (Math.floor(T1 / DAY) + 1) * DAY;
let R = {a: FA, b: FB};
const isFull = () => R.a <= FA && R.b >= FB;
const inR = t => t != null && t >= R.a && t < R.b;
function pIn(p){
  if (p[3] != null && p[4] != null) return p[3] < R.b && p[4] > R.a;
  const t = p[3] != null ? p[3] : p[4];
  return t == null ? isFull() : inR(t);
}
function setRange(a, b){
  a = Math.max(FA, Math.min(a, FB - 60e6)); b = Math.min(FB, Math.max(b, a + 60e6));
  R = {a, b}; refreshRange();
}

// ── filters ──────────────────────────────────────────────────────
const lanes = {Screen: false, Lock: false, Moments: false};
let hideShort = true;
const shortOk = p => !hideShort || p[5] == null || p[5] >= SHORT;
const actCount = {};
const ACTS = [];
P.forEach(p => { const b = base(p[2]); if (!(b in actCount)) { actCount[b] = 0; ACTS.push(b); } actCount[b]++; });
ACTS.sort((x, y) => (rank[x] ?? 99) - (rank[y] ?? 99) || (x < y ? -1 : 1));
let actOn = new Set(ACTS);
const actOk = p => actOn.has(base(p[2]));

// ── day aggregates (brush, calendar, heat) ───────────────────────
let AGG = new Map();
function buildAgg(){
  AGG = new Map();
  const g = d => { let o = AGG.get(d); if (!o) { o = {on: 0, sleep: 0, off: 0, scr: 0, ev: 0}; AGG.set(d, o); } return o; };
  for (const p of P){
    if (!hostOk(p[0]) || p[3] == null || p[4] == null) continue;
    const k = kindOf(p); if (!k) continue;
    let s = p[3]; const e = p[4];
    while (s < e){ const d = Math.floor(s / DAY), nx = Math.min(e, (d + 1) * DAY); g(d)[k] += nx - s; s = nx; }
  }
  for (const e of E) if (hostOk(e[2]) && e[0] != null && e[7] < 0) g(Math.floor(e[0] / DAY)).ev++;
}
const lvl = on => { const hrs = on / HOUR; return hrs <= 0 ? 0 : hrs <= 2 ? 1 : hrs <= 4 ? 2 : hrs <= 8 ? 3 : hrs <= 12 ? 4 : 5; };
function dayTip(d){
  const o = AGG.get(d), t = d * DAY, dt = new Date(t / 1000);
  let s = `<b>${WEEK[dt.getUTCDay()]} ${niceDay(t)}</b>`;
  if (!o) return s + "<br>No records";
  s += `<br>On <b>${fmtTotal(o.on)}</b>`;
  if (o.sleep) s += ` · asleep ${fmtTotal(o.sleep)}`;
  if (o.off) s += ` · shut down ${fmtTotal(o.off)}`;
  if (o.scr) s += `<br>Screen on ${fmtTotal(o.scr)}`;
  return s + `<br><span class="m">${fmtN(o.ev)} events</span>`;
}

// ── brush ────────────────────────────────────────────────────────
const brush = $("brush"), hit = $("b-hit");
const NDAYS = Math.max(1, Math.round((FB - FA) / DAY));
function brushRender(){
  const d0 = FA / DAY; let r = "";
  for (let i = 0; i < NDAYS; i++){
    const o = AGG.get(d0 + i); if (!o) continue;
    const hOn = o.on / DAY * 48, hS = o.sleep / DAY * 48;
    if (hOn > 0) r += `<rect class="b-on" x="${i + 0.12}" y="${(52 - hOn).toFixed(2)}" width="0.76" height="${hOn.toFixed(2)}"/>`;
    if (hS > 0) r += `<rect class="b-sl" x="${i + 0.12}" y="${(52 - hOn - hS).toFixed(2)}" width="0.76" height="${hS.toFixed(2)}"/>`;
    if (!(hOn > 0) && !(hS > 0)) r += `<rect class="b-ev" x="${i + 0.3}" y="49" width="0.4" height="3"/>`;
  }
  const svg = brush.querySelector("svg");
  svg.setAttribute("viewBox", `0 0 ${NDAYS} 52`); svg.innerHTML = r;
  let m = "", dt = new Date(FA / 1000); dt = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), 1));
  // At least ~46 px per label, so months never run into each other.
  const months = Math.max(1, NDAYS / 30.4), px = (brush.clientWidth || 800) / months;
  const every = [1, 2, 3, 6, 12].find(n => px * n >= 46) || 12;
  for (let k = 0; dt.getTime() * 1000 < FB; k++){
    const t = dt.getTime() * 1000;
    if (t >= FA && k % every === 0) m += `<span style="left:${((t - FA) / (FB - FA) * 100).toFixed(3)}%">${MON[dt.getUTCMonth()]}${dt.getUTCMonth() === 0 || k === 0 ? " " + dt.getUTCFullYear() : ""}</span>`;
    dt = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth() + 1, 1));
  }
  brush.querySelector(".months").innerHTML = m;
  brushSel(R.a, R.b);
}
function brushSel(a, b){
  const span = FB - FA, l = (a - FA) / span * 100, w = (b - a) / span * 100;
  $("b-sel").style.left = l + "%"; $("b-sel").style.width = w + "%";
  $("dim-l").style.left = "0"; $("dim-l").style.width = l + "%";
  $("dim-r").style.left = (l + w) + "%"; $("dim-r").style.width = Math.max(0, 100 - l - w) + "%";
  brush.classList.toggle("full", a <= FA && b >= FB);
  $("range-when").innerHTML = whenText(a, b);
  hit.setAttribute("aria-valuetext", whenText(a, b).replace(/<[^>]+>/g, ""));
  hit.setAttribute("aria-valuemin", "0"); hit.setAttribute("aria-valuemax", String(NDAYS));
  hit.setAttribute("aria-valuenow", String(Math.round((a - FA) / DAY)));
}
function whenText(a, b){
  const days = (b - a) / DAY;
  const whole = a % DAY === 0 && b % DAY === 0;
  const txt = whole ? (days === 1 ? niceDay(a) : `${niceDay(a)} – ${niceDay(b - DAY)}`) : `${niceDT(a)} – ${niceDT(b)} UTC`;
  return `<b>${txt}</b> · ${days >= 1 ? fmtN(Math.round(days * 10) / 10) + (days === 1 ? " day" : " days") : fmtTotal(b - a)}${a <= FA && b >= FB ? " (whole log)" : ""}`;
}
(() => {
  let drag = null;
  const tAt = ev => { const r = hit.getBoundingClientRect(); return FA + Math.max(0, Math.min(1, (ev.clientX - r.left) / r.width)) * (FB - FA); };
  const nearEdge = ev => {
    if (isFull()) return null;
    const r = hit.getBoundingClientRect(), x = ev.clientX - r.left, span = FB - FA;
    const xl = (R.a - FA) / span * r.width, xr = (R.b - FA) / span * r.width;
    return Math.abs(x - xl) < 8 ? "a" : Math.abs(x - xr) < 8 ? "b" : null;
  };
  hit.addEventListener("pointerdown", ev => {
    if (ev.button !== 0) return;
    const t = tAt(ev), e = nearEdge(ev);
    drag = {edge: e, anchor: e === "a" ? R.b : e === "b" ? R.a : Math.floor(t / DAY) * DAY, moved: false, cur: [R.a, R.b], x: ev.clientX};
    hit.setPointerCapture(ev.pointerId); tipHide();
  });
  hit.addEventListener("pointermove", ev => {
    if (!drag){
      hit.classList.toggle("edge", !!nearEdge(ev));
      const d = Math.floor(tAt(ev) / DAY); tipShow(dayTip(d), ev); return;
    }
    if (Math.abs(ev.clientX - drag.x) > 3) drag.moved = true;
    if (!drag.moved) return;
    const t = tAt(ev);
    let a, b;
    if (drag.edge){ const tr = Math.round(t / DAY) * DAY; a = Math.min(drag.anchor, tr); b = Math.max(drag.anchor, tr); if (a === b) b = a + DAY; }
    else { const d = Math.floor(t / DAY) * DAY; a = Math.min(drag.anchor, d); b = Math.max(drag.anchor, d) + DAY; }
    a = Math.max(FA, a); b = Math.min(FB, b);
    drag.cur = [a, b]; brushSel(a, b);
  });
  hit.addEventListener("pointerup", ev => {
    if (!drag) return;
    const d = drag; drag = null;
    if (!d.moved){ const day = Math.floor(tAt(ev) / DAY) * DAY; setRange(day, day + DAY); }
    else setRange(d.cur[0], d.cur[1]);
  });
  hit.addEventListener("pointerleave", tipHide);
  hit.addEventListener("dblclick", () => setRange(FA, FB));
  hit.addEventListener("keydown", ev => {
    const step = ev.shiftKey ? 7 * DAY : DAY, w = R.b - R.a;
    if (ev.key === "ArrowLeft"){ ev.preventDefault(); const a = Math.max(FA, R.a - step); setRange(a, a + w); }
    else if (ev.key === "ArrowRight"){ ev.preventDefault(); const b = Math.min(FB, R.b + step); setRange(b - w, b); }
    else if (ev.key === "Home" || ev.key === "Escape"){ ev.preventDefault(); setRange(FA, FB); }
  });
})();
document.querySelectorAll("[data-preset]").forEach(b => b.addEventListener("click", () => {
  const v = b.getAttribute("data-preset");
  if (v === "all") return setRange(FA, FB);
  const end = Math.floor(T1 / DAY) * DAY + DAY;
  setRange(end - (+v) * DAY, end);
}));
function syncPresets(){
  const end = Math.floor(T1 / DAY) * DAY + DAY;
  document.querySelectorAll("[data-preset]").forEach(b => {
    const v = b.getAttribute("data-preset");
    b.setAttribute("aria-pressed", v === "all" ? String(isFull()) : String(R.b === end && R.a === Math.max(FA, end - (+v) * DAY) && !isFull()));
  });
}
const inFrom = $("r-from"), inTo = $("r-to");
const toInput = us => isoOf(us).slice(0, 16);
const fromInput = v => { const t = Date.parse(v + ":00Z"); return isNaN(t) ? null : t * 1000; };
inFrom.min = inTo.min = toInput(FA); inFrom.max = inTo.max = toInput(FB);
inFrom.addEventListener("change", () => { const t = fromInput(inFrom.value); if (t != null) setRange(t, Math.max(R.b, t + HOUR)); });
inTo.addEventListener("change", () => { const t = fromInput(inTo.value); if (t != null) setRange(Math.min(R.a, t - HOUR), t); });
$("chip-x").addEventListener("click", () => setRange(FA, FB));

// ── calendar ─────────────────────────────────────────────────────
let calAnchor = null;
function calRender(){
  let html = "", dt = new Date(FA / 1000);
  dt = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), 1));
  while (dt.getTime() * 1000 < FB){
    const y = dt.getUTCFullYear(), mo = dt.getUTCMonth(), lead = (dt.getUTCDay() + 6) % 7;
    const n = new Date(Date.UTC(y, mo + 1, 0)).getUTCDate();
    let g = "MTWTFSS".split("").map(c => `<span class="wd">${c}</span>`).join("") + "<span></span>".repeat(lead);
    for (let k = 1; k <= n; k++){
      const t = Date.UTC(y, mo, k) * 1000, d = t / DAY, o = AGG.get(d);
      if (t < FA || t >= FB){ g += "<span></span>"; continue; }
      g += `<button type="button" data-d="${d}" class="${o ? "l" + lvl(o.on) : "nd"}" aria-label="${niceDay(t)}${o ? ", on " + fmtTotal(o.on) : ", no records"}"></button>`;
    }
    html += `<div class="cal-m"><div class="cal-t">${MON[mo]} ${y}</div><div class="cal-g">${g}</div></div>`;
    dt = new Date(Date.UTC(y, mo + 1, 1));
  }
  $("cal").innerHTML = html; calSel();
}
function calSel(){
  const full = isFull();
  $("cal").querySelectorAll("button[data-d]").forEach(b => { const t = +b.getAttribute("data-d") * DAY; b.classList.toggle("in", !full && t < R.b && t + DAY > R.a); });
}
$("cal").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-d]"); if (!b) return;
  const d = +b.getAttribute("data-d");
  if (ev.shiftKey && calAnchor != null){ const a = Math.min(calAnchor, d), z = Math.max(calAnchor, d); setRange(a * DAY, (z + 1) * DAY); }
  else { calAnchor = d; setRange(d * DAY, (d + 1) * DAY); }
});
$("cal").addEventListener("mouseover", ev => { const b = ev.target.closest("button[data-d]"); if (b) tipShow(dayTip(+b.getAttribute("data-d")), ev); });
$("cal").addEventListener("mousemove", tipMove);
$("cal").addEventListener("mouseout", ev => { if (ev.target.closest("button[data-d]")) tipHide(); });

// ── usual hours ──────────────────────────────────────────────────
const WD = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
function heatRender(){
  const on = new Float64Array(168), slots = new Float64Array(168);
  for (let d = Math.floor(R.a / DAY); d * DAY < R.b; d++){
    if (!AGG.has(d)) continue;
    const wd = (new Date(d * DAY / 1000).getUTCDay() + 6) % 7;
    for (let hh = 0; hh < 24; hh++){ const s = d * DAY + hh * HOUR, ov = Math.min(R.b, s + HOUR) - Math.max(R.a, s); if (ov > 0) slots[wd * 24 + hh] += ov; }
  }
  for (const p of P){
    if (!hostOk(p[0]) || p[1] !== "Power" || base(p[2]) !== "On" || p[3] == null || p[4] == null) continue;
    let s = Math.max(p[3], R.a); const e = Math.min(p[4], R.b);
    while (s < e){
      const hs = Math.floor(s / HOUR) * HOUR, nx = Math.min(e, hs + HOUR);
      const wd = (new Date(hs / 1000).getUTCDay() + 6) % 7, hh = (hs / HOUR) % 24;
      on[wd * 24 + hh] += nx - s; s = nx;
    }
  }
  let mx = 0; for (let k = 0; k < 168; k++) if (slots[k]) mx = Math.max(mx, on[k] / slots[k]);
  $("heat-max").textContent = mx ? `darkest = on ${Math.round(Math.min(1, mx) * 100)}% of that hour` : "";
  let html = '<span></span>' + Array.from({length: 24}, (_, i) => `<span class="hl">${i % 3 === 0 ? pad(i) : ""}</span>`).join("");
  for (let w = 0; w < 7; w++){
    html += `<span class="dl">${WD[w]}</span>`;
    for (let hh = 0; hh < 24; hh++){
      const k = w * 24 + hh, sl = slots[k], pct = sl ? Math.min(1, on[k] / sl) : 0;
      const l = !sl || pct <= 0 || !mx ? 0 : Math.max(1, Math.ceil(pct / Math.min(1, mx) * 5));
      html += `<i role="img" class="${l ? "l" + l : ""}" data-h="${w},${hh},${sl ? Math.round(pct * 100) : -1}" aria-label="${WD[w]} ${pad(hh)}:00, ${sl ? Math.round(pct * 100) + "% on" : "no records"}"></i>`;
    }
  }
  $("heat").innerHTML = html;
}
$("heat").addEventListener("mouseover", ev => {
  const i = ev.target.closest("i[data-h]"); if (!i) return;
  const [w, hh, pc] = i.getAttribute("data-h").split(",").map(Number);
  tipShow(`<b>${WD[w]} ${pad(hh)}:00–${pad(hh + 1 === 24 ? 0 : hh + 1)}:00 UTC</b><br>${pc < 0 ? "No records" : `On ${pc}% of the time`}`, ev);
});
$("heat").addEventListener("mousemove", tipMove);
$("heat").addEventListener("mouseout", tipHide);

// ── overview ─────────────────────────────────────────────────────
function overview(){
  const hs = hostSel < 0 ? D.hosts.map((_, i) => hostName(i)) : [hostName(hostSel)];
  $("h-ov").textContent = "System activity" + (hs.length === 1 ? " on " + hs[0] : ` on ${hs.length} computers`);
  const acc = {}, unknown = [0];
  let pn = 0, unp = 0, unpN = 0;
  for (const p of P){
    if (!hostOk(p[0]) || !pIn(p)) continue;
    pn++;
    if (p[3] != null && p[4] != null && p[5] == null){
      // Start and end are known but the clock was changed in between, so the
      // analysis does not prove the length: shown apart, by the clock.
      unknown[0]++;
      if (p[1] === "Power"){ const ov = Math.min(p[4], R.b) - Math.max(p[3], R.a); if (ov > 0){ unp += ov; unpN++; } }
      continue;
    }
    if (p[3] == null || p[4] == null || p[5] == null){ unknown[0]++; continue; }
    const ov = Math.min(p[4], R.b) - Math.max(p[3], R.a); if (ov <= 0) continue;
    const k = p[1] + "\u0001" + base(p[2]);
    const a = acc[k] || (acc[k] = [0, 0]); a[0] += ov; a[1]++;
  }
  const covA = Math.max(R.a, T0 ?? R.a), covB = Math.min(R.b, (T1 ?? R.b) + 1), cov = Math.max(0, covB - covA);
  const layers = [];
  for (const L of ["Power", "Screen", "Lock"]){
    const items = Object.keys(acc).filter(k => k.split("\u0001")[0] === L).map(k => [k.split("\u0001")[1], acc[k][0], acc[k][1]])
      .sort((x, y) => (rank[x[0]] ?? 99) - (rank[y[0]] ?? 99) || (x[0] < y[0] ? -1 : 1));
    if (items.length) layers.push([L, items]);
  }
  const pw = layers.find(l => l[0] === "Power"), sc = layers.find(l => l[0] === "Screen");
  const sum = (l, f) => l ? l[1].filter(x => f(x[0])).reduce((a, x) => a + x[1], 0) : 0;
  const onT = sum(pw, s => s === "On"), offT = sum(pw, s => stKey(s) === "off" || stKey(s) === "crash"), slT = sum(pw, s => s !== "On" && stKey(s) !== "off" && stKey(s) !== "crash");
  const scrT = sum(sc, s => s === "Screen on");
  const who = hs.length === 1 ? h(hs[0]) : "these computers";
  let lede = `${isFull() ? "Across the whole log" : "In this range"} (<b>${whenText(R.a, R.b).replace(/<[^>]+>/g, "").replace(/ · .*/, "")}</b>), ${who} was <b>on for ${fmtTotal(onT)}</b>`;
  if (slT) lede += `, asleep or in low power for <b>${fmtTotal(slT)}</b>`;
  if (offT) lede += `, and shut down for <b>${fmtTotal(offT)}</b>`;
  lede += ".";
  if (scrT) lede += ` The screen was on for <b>${fmtTotal(scrT)}</b>.`;
  lede += " All times are UTC.";
  $("ov-lede").innerHTML = lede;
  let mn = 0, en = 0, dn = 0;
  for (const m of M) if (hostOk(m[0]) && inR(m[1])) mn++;
  for (const e of E) if (hostOk(e[2]) && inR(e[0])) { if (e[7] < 0) en++; else dn++; }
  const daysRec = [...AGG.keys()].filter(d => d * DAY < R.b && (d + 1) * DAY > R.a).length;
  $("facts").innerHTML = [["Days with records", fmtN(daysRec)], ["Periods", fmtN(pn)], ["Moments", fmtN(mn)],
    ["Raw events", fmtN(en) + (dn ? ` <small>+ ${fmtN(dn)} copies</small>` : "")], ["Log files", fmtN(D.files.filter(Boolean).length)],
    ["Log span", `${h(D.meta.first)} <small>to</small> ${h(D.meta.last)} <small>UTC</small>`]]
    .map(x => `<div><dt>${x[0]}</dt><dd>${x[1]}</dd></div>`).join("");
  $("layers").innerHTML = layers.map(L => {
    let items = L[1].slice(), total = items.reduce((a, s) => a + s[1], 0);
    const u = L[0] === "Power" ? unp : 0;
    const none = L[0] === "Power" && cov > total + u ? cov - total - u : 0;
    const denom = Math.max(total + u + none, 1);
    const rows = items.map(s => `<tr title="Exact: ${fmtExact(s[1])}"><td><span class="sw st-${stKey(s[0])}"></span>${h(s[0])}</td><td class="num"><b>${fmtTotal(s[1])}</b></td><td class="num dim">${pctTxt(s[1] / denom)}</td><td class="num dim">${fmtN(s[2])} ${s[2] === 1 ? "period" : "periods"}</td></tr>`).join("")
      + (u ? `<tr class="none" title="Periods with a known start and end whose length is not proven: the system clock was changed in between. Measured by the clock."><td><span class="sw unp"></span>Length unproven (clock changed)</td><td class="num">${fmtTotal(u)}</td><td class="num">${pctTxt(u / denom)}</td><td class="num">${fmtN(unpN)} ${unpN === 1 ? "period" : "periods"}</td></tr>` : "")
      + (none ? `<tr class="none" title="Time in the range with no power period proven by the events"><td><span class="sw none"></span>No power record</td><td class="num">${fmtTotal(none)}</td><td class="num">${pctTxt(none / denom)}</td><td></td></tr>` : "");
    const bar = items.map(s => `<i class="st-${stKey(s[0])}" style="flex:${s[1]} 0 0"></i>`).join("") + (u ? `<i class="unp" style="flex:${u} 0 0"></i>` : "") + (none ? `<i class="none" style="flex:${none} 0 0"></i>` : "");
    const sub = L[0] === "Power" ? "share of the time range" : L[0] === "Screen" ? "while Windows recorded screen sessions" : "needs lock auditing";
    return `<div class="panel layer"><div class="ph"><h3>${L[0]}</h3><span class="sub">${sub}</span></div><div class="stack" role="img" aria-label="${L[0]} time by state">${bar}</div><table class="ltab"><tbody>${rows}</tbody></table></div>`;
  }).join("") || `<div class="panel layer"><div class="ph"><h3>No periods in this range</h3></div><p class="lede" style="padding:8px 18px 0">Pick a wider range, or the whole log.</p></div>`;
  let notes = "";
  if (unknown[0]) notes += `<div class="note warn">${icon("alert")}<span>${fmtN(unknown[0])} period${unknown[0] === 1 ? " has" : "s have"} an unproven start, end or length and ${unknown[0] === 1 ? "is" : "are"} not in the state totals; where both ends are known their clock span is shown as "Length unproven".</span></div>`;
  for (const t of coverageNotes()) notes += `<div class="note warn">${icon("alert")}<span>${h(t)}</span></div>`;
  for (const [cls, t] of clockNotes()) notes += `<div class="note ${cls}">${icon(cls ? "alert" : "info")}<span>${h(t)}</span></div>`;
  for (const t of sessionTypeNotes()) notes += `<div class="note">${icon("info")}<span>${h(t)}</span></div>`;
  if (!isFull()) notes += `<div class="note">${icon("info")}<span>Periods that cross the range edges count only their part inside it.</span></div>`;
  notes += `<div class="note">${icon("info")}<span>${h(D.meta.coverage)}</span></div>`;
  $("ov-notes").innerHTML = notes;
}
// Undocumented Kernel-Power 566 session types (e.g. 2): what the events in
// the range show about them, counted -- never a guessed name.
const TYPE_NAME = {0: "screen on", 1: "screen off", 3: "sleep"};
function sessionTypeNotes(){
  const types = new Set();
  for (const p of P){ const mm = /^Session type (\d+)/.exec(p[2]); if (mm && hostOk(p[0]) && pIn(p)) types.add(+mm[1]); }
  const out = [];
  for (const ty of types){
    const from = {}, to = {}; let n = 0, mx = 0, atMx = 0;
    for (const e of E){
      if (e[3] !== "Kernel-Power 566" || e[7] >= 0 || !hostOk(e[2]) || !inR(e[0])) continue;
      const d = {}; for (const r of e[9]) d[r[0]] = r[1];
      if (+d.NextSessionType === ty) from[d.PreviousSessionType] = (from[d.PreviousSessionType] || 0) + 1;
      if (+d.PreviousSessionType === ty){
        n++; to[d.NextSessionType] = (to[d.NextSessionType] || 0) + 1;
        const us = +d.PreviousSessionDurationInUs || 0;
        if (us > mx + 1e6){ mx = us; atMx = 1; } else if (Math.abs(us - mx) <= 1e6) atMx++;
      }
    }
    const list = o => Object.keys(o).sort((a, b) => o[b] - o[a]).map(k => `${TYPE_NAME[k] || "type " + k} (${fmtN(o[k])})`).join(", ");
    const fromN = Object.values(from).reduce((a, b) => a + b, 0);
    let t = `Session type ${ty} is not documented by Microsoft and EventHawk does not name it. In these events it`;
    if (fromN) t += ` starts after ${list(from)}`;
    if (n) t += `${fromN ? "," : ""} lasts up to ${fmtTotal(mx)}${atMx > 2 ? ` (${fmtN(atMx)} end at that length, which looks like a Windows timeout)` : ""}, and ends in ${list(to)}`;
    out.push(t + ".");
  }
  return out;
}
// Logs keep different spans (System rolls over sooner than Diagnostics-
// Performance): say so, or "No power record" reads as "switched off".
function coverageNotes(){
  const span = {};
  for (const e of E){
    if (e[0] == null || e[7] >= 0 || !hostOk(e[2])) continue;
    const s = span[e[5]] || (span[e[5]] = [e[0], e[0], 0]);
    if (e[0] < s[0]) s[0] = e[0]; if (e[0] > s[1]) s[1] = e[0]; s[2]++;
  }
  const ks = Object.keys(span);
  if (ks.length < 2) return [];
  const firsts = ks.map(k => span[k][0]);
  if (Math.max(...firsts) - Math.min(...firsts) < 7 * DAY) return [];
  ks.sort((a, b) => span[a][0] - span[b][0]);
  return [`The logs cover different spans: ${ks.map(k => `${shortFile(D.files[k]) || "(no file name)"} ${niceDay(span[k][0])} – ${niceDay(span[k][1])} (${fmtN(span[k][2])} events)`).join("; ")}. `
    + "Before a log's first event it has no records, so “No power record” there means the log had rolled over, not that the computer was off. Pick a range inside the System log's span for complete totals."];
}
const signed = us => (us >= 0 ? "+" : "\u2212") + fmtTotal(Math.abs(us));
function clockTip(c){
  return `<b>Clock changed ${signed(c[1])}</b><br><span class="m">${h(fmtDT(c[0]))} UTC</span><br>${h(c[2] || "")}`
    + `<br>${c[5] ? "On waking: Windows catching up with the hardware clock after the sleep" : "While running: later times are on the new clock"}`;
}
function clockNotes(){
  const cs = D.clock.filter(c => hostOk(c[4]) && inR(c[0]));
  if (!cs.length) return [];
  const wake = cs.filter(c => c[5]), run = cs.filter(c => !c[5]);
  let t = `${fmtN(cs.length)} clock change${cs.length === 1 ? "" : "s"} of a minute or more in this range (marked on the day-by-day view).`;
  if (wake.length) t += ` ${fmtN(wake.length)} ${wake.length === 1 ? "was" : "were"} made on waking: Windows catching up with the hardware clock after a sleep, so the sleep's own times stay right.`;
  if (run.length){
    const big = run.reduce((a, c) => Math.abs(c[1]) > Math.abs(a[1]) ? c : a);
    t += ` ${fmtN(run.length)} ${run.length === 1 ? "was" : "were"} made while running (largest ${signed(big[1])} at ${fmtDT(big[0])} UTC): event times before such a change are as the clock showed them then, and a period that spans one shows its length as Unavailable rather than a wrong number.`;
  }
  return [[run.length ? "warn" : "", t]];
}
const pctTxt = f => { const p = f * 100; return p <= 0 ? "0%" : p < 0.1 ? "<0.1%" : p.toFixed(p < 10 ? 1 : 0) + "%"; };

// ── activities filter ────────────────────────────────────────────
function actsRender(){
  const laneOf = {}; P.forEach(p => { laneOf[base(p[2])] = p[1]; });
  $("acts").innerHTML = ACTS.filter(a => laneOf[a] === "Power" || lanes[laneOf[a]]).map(a => `<button type="button" class="act" data-act="${h(a)}" aria-pressed="${actOn.has(a)}" title="Click to show or hide; double-click to show only this"><span class="sw st-${stKey(a)}"></span>${h(a)}<span class="c">${fmtN(actCount[a])}</span></button>`).join("")
    + (actOn.size < ACTS.length ? `<button type="button" class="reset" data-act-all>Show all</button>` : "");
  $("dd-acts-pop").innerHTML = ACTS.map(a => `<label><input type="checkbox" data-act="${h(a)}" ${actOn.has(a) ? "checked" : ""}><span class="sw st-${stKey(a)}"></span>${h(a)}<button type="button" class="only" data-only="${h(a)}">only</button><span class="c">${fmtN(actCount[a])}</span></label>`).join("")
    + `<div class="ft"><button type="button" data-act-all>Show all</button><button type="button" data-act-none>Power on only</button></div>`;
  $("dd-acts-l").textContent = actOn.size === ACTS.length ? "All activities" : `${actOn.size} of ${ACTS.length} activities`;
}
function setActs(set){ actOn = set; if (!actOn.size) actOn = new Set(ACTS); actsRender(); tlRender(); periodsT.refilter(); }
let actClickT = null;
$("acts").addEventListener("click", ev => {
  if (ev.target.closest("[data-act-all]")) return setActs(new Set(ACTS));
  const b = ev.target.closest("[data-act]"); if (!b) return;
  const a = b.getAttribute("data-act");
  clearTimeout(actClickT);
  actClickT = setTimeout(() => { const s = new Set(actOn); s.has(a) ? s.delete(a) : s.add(a); setActs(s); }, 180);
});
$("acts").addEventListener("dblclick", ev => { const b = ev.target.closest("[data-act]"); if (!b) return; clearTimeout(actClickT); setActs(new Set([b.getAttribute("data-act")])); });
$("dd-acts-pop").addEventListener("click", ev => {
  if (ev.target.closest("[data-act-all]")) return setActs(new Set(ACTS));
  if (ev.target.closest("[data-act-none]")) return setActs(new Set(ACTS.filter(a => a === "On")));
  const o = ev.target.closest("[data-only]"); if (o){ ev.preventDefault(); return setActs(new Set([o.getAttribute("data-only")])); }
});
$("dd-acts-pop").addEventListener("change", ev => {
  const c = ev.target.closest("input[data-act]"); if (!c) return;
  const s = new Set(actOn); c.checked ? s.add(c.getAttribute("data-act")) : s.delete(c.getAttribute("data-act")); setActs(s);
});
document.addEventListener("click", ev => { const dd = $("dd-acts"); if (dd.open && !dd.contains(ev.target)) dd.open = false; });

// lanes / short
$("lanes").addEventListener("click", ev => { const b = ev.target.closest("[data-lane]"); if (!b) return; const l = b.getAttribute("data-lane"); lanes[l] = !lanes[l]; b.setAttribute("aria-pressed", String(lanes[l])); actsRender(); tlRender(); });
function syncShort(){ $("tl-short").checked = hideShort; $("p-short").checked = hideShort; }
["tl-short", "p-short"].forEach(id => $(id).addEventListener("change", function(){ hideShort = this.checked; syncShort(); tlRender(); periodsT.refilter(); }));

// ── day by day ───────────────────────────────────────────────────
const TL_PAGE = 31;
let tlAll = false, tlSel = null;
function tlRender(){
  const el = $("tl"), days = new Map();
  const bucket = d => { let o = days.get(d); if (!o) { o = {h: [], on: 0, two: false}; days.set(d, o); } return o; };
  for (let i = 0; i < P.length; i++){
    const p = P[i];
    if (!hostOk(p[0]) || !actOk(p) || !shortOk(p)) continue;
    const L = p[1];
    if (L === "Screen" && !lanes.Screen) continue;
    if (L === "Lock" && !lanes.Lock) continue;
    const k = stKey(p[2]);
    const cls = L === "Power" ? `lp st-${k}${k !== "on" && k !== "off" && k !== "crash" ? " soft" : ""}` : (L === "Screen" ? "ls" : "ll") + " st-" + k;
    if (p[3] != null && p[4] != null){
      if (!(p[3] < R.b && p[4] > R.a)) continue;
      const s0 = Math.max(p[3], R.a), e0 = Math.min(p[4], R.b);
      for (let d = Math.floor(s0 / DAY); d * DAY < e0; d++){
        const a = Math.max(s0, d * DAY), b = Math.min(e0, (d + 1) * DAY);
        if (b <= a) continue;
        const bk = bucket(d);
        if (L !== "Power") bk.two = true;
        if (L === "Screen" && base(p[2]) !== "Screen on") continue;
        bk.h.push(`<i class="${cls}" data-p="${i}" style="left:${((a - d * DAY) / DAY * 100).toFixed(4)}%;width:${((b - a) / DAY * 100).toFixed(4)}%"></i>`);
        if (L === "Power" && k === "on") bk.on += b - a;
      }
    } else {
      const t = p[3] != null ? p[3] : p[4];
      if (!inR(t)) continue;
      const d = Math.floor(t / DAY);
      bucket(d).h.push(`<i class="edge" data-p="${i}" style="left:${((t - d * DAY) / DAY * 100).toFixed(4)}%"></i>`);
    }
  }
  if (lanes.Moments){
    for (let j = 0; j < M.length; j++){
      const m = M[j];
      if (!hostOk(m[0]) || !inR(m[1]) || (mKind && m[3] !== mKind)) continue;
      const d = Math.floor(m[1] / DAY);
      bucket(d).h.push(`<i class="tk" data-m="${j}" style="left:${((m[1] - d * DAY) / DAY * 100).toFixed(4)}%"></i>`);
    }
  }
  // Clock changes: always drawn (a running change moves every later time).
  D.clock.forEach((c, j) => {
    if (!hostOk(c[4]) || !inR(c[0])) return;
    const d = Math.floor(c[0] / DAY);
    bucket(d).h.push(`<i class="clk${c[5] ? " wake" : ""}" data-c="${j}" style="left:${((c[0] - d * DAY) / DAY * 100).toFixed(4)}%"></i>`);
  });
  for (const d of AGG.keys()) if (d * DAY < R.b && (d + 1) * DAY > R.a) bucket(d);
  const keys = [...days.keys()].sort((a, b) => a - b);
  const axis = `<div class="tl-axis" aria-hidden="true"><span>UTC day</span><div class="hours">${[0, 6, 12, 18, 24].map(x => `<span style="left:${x / 24 * 100}%">${pad(x)}:00</span>`).join("")}</div><span style="text-align:right">On</span></div>`;
  if (!keys.length){ el.innerHTML = axis + `<div class="tl-empty">Nothing recorded in this range for the activities shown.</div>`; return; }
  const shown = tlAll ? keys : keys.slice(-TL_PAGE);
  const gl = [3, 6, 9, 12, 15, 18, 21].map(x => `<span class="gl" style="left:${x / 24 * 100}%"></span>`).join("");
  const out = [axis];
  if (!tlAll && keys.length > TL_PAGE) out.push(`<div class="more" style="border-top:0;border-bottom:1px solid var(--line)"><button class="btn" type="button" id="tl-more">Show all ${fmtN(keys.length)} days (${fmtN(keys.length - TL_PAGE)} earlier)</button></div>`);
  let prev = null;
  for (const d of shown){
    if (prev != null && d - prev > 1){ const n = d - prev - 1; out.push(`<div class="gap">No records for ${n === 1 ? "1 day" : n + " days"}</div>`); }
    prev = d;
    const bk = days.get(d), dt = new Date(d * DAY / 1000), wd = dt.getUTCDay();
    out.push(`<div class="day${wd === 0 || wd === 6 ? " we" : ""}"><div class="dl">${WEEK[wd]}<b>${dt.getUTCDate()} ${MON[dt.getUTCMonth()]}<span class="y"> ${dt.getUTCFullYear()}</span></b></div><div class="track${bk.two || lanes.Moments ? " two" : ""}">${gl}${bk.h.join("")}</div><div class="dsum">${bk.on ? "<b>" + fmtTotal(bk.on) + "</b>" : "—"}</div></div>`);
  }
  el.innerHTML = out.join("");
  const more = $("tl-more"); if (more) more.addEventListener("click", () => { tlAll = true; tlRender(); });
  if (tlSel) markTl(tlSel);
}
function markTl(key){
  const el = $("tl");
  el.querySelectorAll("i.sel").forEach(i => i.classList.remove("sel"));
  tlSel = key; if (!key) return;
  el.querySelectorAll(`i[data-${key[0]}="${key[1]}"]`).forEach(i => i.classList.add("sel"));
}
(() => {
  const el = $("tl");
  el.addEventListener("mouseover", ev => {
    const t = ev.target; if (t.tagName !== "I" || t.classList.contains("gl")) return;
    if (t.hasAttribute("data-p")){ const p = P[+t.getAttribute("data-p")]; tipShow(`<b>${h(p[2])}</b> · ${h(p[1])}<br><span class="m">${h(p[6])} → ${h(p[7])}</span><br>${h(p[8])}`, ev); }
    else if (t.hasAttribute("data-c")){ tipShow(clockTip(D.clock[+t.getAttribute("data-c")]), ev); }
    else if (t.hasAttribute("data-m")){ const m = M[+t.getAttribute("data-m")]; tipShow(`<b>${h(m[3])}</b><br><span class="m">${h(m[2])}</span>${m[4] ? "<br>" + h(m[4].length > 140 ? m[4].slice(0, 140) + "…" : m[4]) : ""}`, ev); }
  });
  el.addEventListener("mousemove", tipMove);
  el.addEventListener("mouseout", ev => { if (ev.target.tagName === "I") tipHide(); });
  el.addEventListener("click", ev => {
    const t = ev.target; if (t.tagName !== "I") return;
    if (t.hasAttribute("data-p")) inspect("p", +t.getAttribute("data-p")); else if (t.hasAttribute("data-m")) inspect("m", +t.getAttribute("data-m"));
    else if (t.hasAttribute("data-c")) inspect("e", D.clock[+t.getAttribute("data-c")][3]);
  });
})();

// ── virtual table ────────────────────────────────────────────────
const RH = 34, HEAD = 38;
class VTable {
  constructor(o){
    this.o = o; this.el = $(o.id); this.rows = []; this.sel = -1; this.sortCol = o.sortCol; this.sortDir = 1; this.full = false;
    this.el.style.setProperty("--cols", o.cols.map(c => c.w).join(" "));
    this.el.style.setProperty("--minw", o.minw + "px");
    this.el.innerHTML = `<div class="th" role="row" aria-rowindex="1">${o.cols.map((c, i) => `<div class="td${c.r ? " r" : ""}" role="columnheader">${c.sort ? `<button type="button" data-c="${i}">${c.label}${icon("down")}</button>` : c.label}</div>`).join("")}</div><div class="body"></div>`;
    this.body = this.el.querySelector(".body");
    let raf = 0;
    this.el.addEventListener("scroll", () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; this.paint(); }); }, {passive: true});
    this.el.querySelector(".th").addEventListener("click", ev => {
      const b = ev.target.closest("button[data-c]"); if (!b) return;
      const c = +b.getAttribute("data-c");
      if (this.sortCol === c) this.sortDir = -this.sortDir; else { this.sortCol = c; this.sortDir = 1; }
      this.sort(); this.paint(true);
    });
    this.body.addEventListener("click", ev => {
      if (ev.target.closest("[data-act=clear]")) return o.clear();
      const r = ev.target.closest(".tr"); if (r) this.select(+r.getAttribute("data-k"), false);
    });
    this.el.addEventListener("keydown", ev => {
      if (ev.target.tagName === "BUTTON") return;
      const k = this.rows.indexOf(this.sel), n = this.rows.length; if (!n) return;
      const page = Math.max(1, Math.floor((this.el.clientHeight - HEAD) / RH) - 1);
      const to = {ArrowDown: k + 1, ArrowUp: k - 1, PageDown: k + page, PageUp: k - page, Home: 0, End: n - 1, Enter: k}[ev.key];
      if (to === undefined) return;
      ev.preventDefault();
      this.select(this.rows[Math.max(0, Math.min(n - 1, to))], true);
    });
    this.sortHead();
  }
  sortHead(){ this.el.querySelectorAll(".th button").forEach(b => { const c = +b.getAttribute("data-c"); b.setAttribute("aria-sort", c === this.sortCol ? (this.sortDir > 0 ? "ascending" : "descending") : "none"); }); }
  sort(){
    const col = this.o.cols[this.sortCol], key = col && col.sort, dir = this.sortDir;
    if (key){
      const keys = new Map(); for (const i of this.rows) keys.set(i, key(i));
      this.rows.sort((a, b) => { const x = keys.get(a), y = keys.get(b); if (x == null && y == null) return a - b; if (x == null) return 1; if (y == null) return -1; return (x < y ? -1 : x > y ? 1 : a - b) * dir; });
    }
    this.sortHead();
  }
  refilter(){
    const t0 = performance.now();
    this.rows = this.o.filter(); this.sort();
    const n = this.rows.length;
    this.el.style.setProperty("--h", (HEAD + Math.max(n, 4) * RH + 2) + "px");
    this.body.style.height = (n * RH) + "px";
    this.el.setAttribute("aria-rowcount", String(n + 1));
    this.a = this.b = -1; this.paint(true);
    if (this.o.count) this.o.count(n);
    (window.__ehPerf = window.__ehPerf || {})[this.o.id] = performance.now() - t0;
  }
  paint(force){
    const n = this.rows.length, top = this.el.scrollTop, vh = this.el.clientHeight || 600;
    const a = this.full ? 0 : Math.max(0, Math.floor((top - HEAD) / RH) - 8), b = this.full ? n : Math.min(n, Math.ceil((top + vh) / RH) + 8);
    if (!force && a === this.a && b === this.b) return;
    this.a = a; this.b = b;
    if (!n){ this.body.innerHTML = `<div class="empty">${h(this.o.emptyText())}<br><button class="btn" type="button" data-act="clear">Clear filters</button></div>`; return; }
    const cols = this.o.cols, q = this.o.terms(), out = [];
    for (let k = a; k < b; k++){
      const i = this.rows[k]; let cells = "";
      for (const co of cols){ const v = co.get(i); cells += `<div class="td${co.cls ? " " + co.cls : ""}" role="gridcell"${co.tip ? ` title="${h(co.tip(i))}"` : ""}>${co.html ? v : hl(v, q)}</div>`; }
      out.push(`<div class="tr${i === this.sel ? " sel" : ""}${this.o.rowCls ? this.o.rowCls(i) : ""}" role="row" aria-rowindex="${k + 2}" aria-selected="${i === this.sel}" data-k="${i}" style="${this.full ? "position:static" : `transform:translateY(${k * RH}px)`}">${cells}</div>`);
    }
    this.body.innerHTML = out.join("");
  }
  select(i, scroll){
    this.sel = i;
    if (scroll){ const k = this.rows.indexOf(i); if (k >= 0){ const y = k * RH, top = this.el.scrollTop, vh = this.el.clientHeight - HEAD; if (y < top) this.el.scrollTop = y; else if (y + RH > top + vh) this.el.scrollTop = y + RH - vh; } }
    this.paint(true); this.o.open(i);
  }
  reveal(i){
    if (this.rows.indexOf(i) < 0) this.o.clear(true);
    if (this.rows.indexOf(i) < 0 && !isFull()){ setRange(FA, FB); }
    this.sel = i;
    const k = this.rows.indexOf(i);
    if (k >= 0) this.el.scrollTop = Math.max(0, k * RH - (this.el.clientHeight - HEAD) / 2);
    this.paint(true);
    this.el.scrollIntoView({block: "nearest"}); this.el.focus({preventScroll: true});
  }
}

// ── search ───────────────────────────────────────────────────────
const terms = s => { s = s.trim().toLowerCase(); return s ? s.split(/\s+/) : null; };
const matchAll = (hay, ts) => { for (const t of ts) if (hay.indexOf(t) < 0) return false; return true; };
function hl(v, ts){
  const s = v == null ? "" : String(v);
  if (!ts || !s) return h(s);
  const low = s.toLowerCase(), marks = [];
  ts.forEach(t => { const p = low.indexOf(t); if (p >= 0) marks.push([p, p + t.length]); });
  if (!marks.length) return h(s);
  marks.sort((a, b) => a[0] - b[0]);
  let out = "", at = 0;
  for (const m of marks){ if (m[0] < at) continue; out += h(s.slice(at, m[0])) + "<mark>" + h(s.slice(m[0], m[1])) + "</mark>"; at = m[1]; }
  return out + h(s.slice(at));
}
const debounce = (fn, ms) => { let t; return () => { clearTimeout(t); t = setTimeout(fn, ms); }; };
const hayOf = (arr, build) => { let cache = null; return i => { if (!cache){ cache = new Array(arr.length); for (let k = 0; k < arr.length; k++) cache[k] = build(arr[k]).toLowerCase(); } return cache[i]; }; };
const recOf = i => i >= 0 ? E[i][6] : "";
const withRec = (label, i) => i >= 0 && E[i][6] !== "" ? `${label} #${E[i][6]}` : label;
const pHay = hayOf(P, p => [hostName(p[0]), p[1], p[2], p[6], p[7], p[8], p[9], p[10], p[11], p[12], "#" + recOf(p[13]), "#" + recOf(p[14])].join("\u0001"));
const mHay = hayOf(M, m => [hostName(m[0]), m[2], m[3], m[4], m[5], "#" + recOf(m[6])].join("\u0001"));
const SYS = D.meta.sys;
const sysRows = ev => { const out = []; ev[8].forEach((v, k) => { if (v != null) out.push([SYS[k], v]); }); if (D.files[ev[5]]) out.push(["Log file", D.files[ev[5]]]); return out; };
const eHay = hayOf(E, e => { const s = [e[1], e[3], e[4], D.files[e[5]], e[6], "#" + e[6], hostName(e[2])]; e[8].forEach((v, k) => { if (v != null) s.push(SYS[k] + " " + v); }); for (const kv of e[9]) s.push(kv[0] + " " + kv[1]); return s.join("\u0001"); });
const shortFile = f => { if (!f) return ""; let b = f.split(/[\\/]/).pop(); try { b = decodeURIComponent(b); } catch(e){} return b.replace(/%4/g, "/"); };
const countTxt = (n, tot, noun) => n === tot ? `<b>${fmtN(n)}</b> ${noun}` : `<b>${fmtN(n)}</b> of ${fmtN(tot)} ${noun}`;
function activityCell(s, q){
  const k = s.indexOf(" (");
  return `<span class="pill"><span class="sw st-${stKey(s)}"></span><span>${hl(k < 0 ? s : s.slice(0, k), q)}</span>${k < 0 ? "" : `<span class="code">${hl(s.slice(k + 2, -1), q)}</span>`}</span>`;
}

// ── periods ──────────────────────────────────────────────────────
const qP = $("q-periods"); let tP = null;
const periodsT = new VTable({
  id: "t-periods", minw: multi ? 1040 : 940, sortCol: multi ? 2 : 1,
  cols: [...(multi ? [{label: "Computer", w: "minmax(90px,.6fr)", get: i => hostName(P[i][0]), sort: i => hostName(P[i][0]).toLowerCase()}] : []),
    {label: "Activity", w: "minmax(170px,1.1fr)", html: true, get: i => activityCell(P[i][2], tP), tip: i => P[i][2] + " · " + P[i][1], sort: i => P[i][2]},
    {label: "Start (UTC)", w: "minmax(140px,.8fr)", cls: "m", get: i => P[i][6], sort: i => P[i][3]},
    {label: "End (UTC)", w: "minmax(140px,.8fr)", cls: "m", get: i => P[i][7], sort: i => P[i][4]},
    {label: "Duration", w: "minmax(90px,.5fr)", cls: "m r", r: true, get: i => P[i][8], tip: i => "Exact: " + P[i][9], sort: i => P[i][5]},
    {label: "Evidence (start → end)", w: "minmax(170px,1.1fr)", cls: "dim", get: i => withRec(P[i][10], P[i][13]) + " → " + withRec(P[i][11], P[i][14]), tip: i => "Started by " + withRec(P[i][10], P[i][13]) + " · Ended by " + withRec(P[i][11], P[i][14])},
    {label: "Notes", w: "minmax(140px,1.4fr)", cls: "dim", get: i => P[i][12], tip: i => P[i][12]}],
  filter(){ const out = [], ts = tP; for (let i = 0; i < P.length; i++){ const p = P[i]; if (hostOk(p[0]) && actOk(p) && shortOk(p) && pIn(p) && (!ts || matchAll(pHay(i), ts))) out.push(i); } return out; },
  terms: () => tP,
  count(n){
    let tot = 0, sh = 0;
    for (const p of P) if (hostOk(p[0]) && pIn(p)) { tot++; if (p[5] != null && p[5] < SHORT) sh++; }
    $("c-periods").innerHTML = countTxt(n, tot, "periods");
    $("p-short-l").textContent = `Hide periods under 1 s (${fmtN(sh)})`;
  },
  emptyText: () => "No periods match. Clear the search, show more activities, or widen the time range.",
  clear(keepRange){ qP.value = ""; tP = null; hideShort = false; syncShort(); actOn = new Set(ACTS); actsRender(); tlRender(); periodsT.refilter(); if (!keepRange && !isFull()) setRange(FA, FB); },
  open: i => inspect("p", i, true)
});
qP.addEventListener("input", debounce(() => { tP = terms(qP.value); periodsT.refilter(); }, 60));

// ── moments ──────────────────────────────────────────────────────
const qM = $("q-moments"); let tM = null, mKind = "";
(() => {
  const c = {}; M.forEach(m => c[m[3]] = (c[m[3]] || 0) + 1);
  const ks = Object.keys(c).sort((a, b) => c[b] - c[a] || (a < b ? -1 : 1));
  $("m-kind").innerHTML = '<option value="">All kinds</option>' + ks.map(k => `<option value="${h(k)}">${h(k)} (${fmtN(c[k])})</option>`).join("");
  $("m-kind").addEventListener("change", function(){ mKind = this.value; momentsT.refilter(); if (lanes.Moments) tlRender(); });
})();
const momentsT = new VTable({
  id: "t-moments", minw: multi ? 1020 : 920, sortCol: multi ? 1 : 0,
  cols: [...(multi ? [{label: "Computer", w: "minmax(90px,.6fr)", get: i => hostName(M[i][0]), sort: i => hostName(M[i][0]).toLowerCase()}] : []),
    {label: "Time (UTC)", w: "minmax(140px,.8fr)", cls: "m", get: i => M[i][2], sort: i => M[i][1]},
    {label: "What happened", w: "minmax(170px,1fr)", get: i => M[i][3], tip: i => M[i][3], sort: i => M[i][3]},
    {label: "Details", w: "minmax(220px,2.2fr)", cls: "dim", get: i => M[i][4], tip: i => M[i][4]},
    {label: "Evidence", w: "minmax(130px,.7fr)", cls: "dim", get: i => M[i][5], sort: i => M[i][5]},
    {label: "Record", w: "80px", cls: "m r", r: true, get: i => M[i][6] >= 0 ? E[M[i][6]][6] : "", sort: i => M[i][6] >= 0 ? +E[M[i][6]][6] || 0 : null}],
  filter(){ const out = [], ts = tM; for (let i = 0; i < M.length; i++){ const m = M[i]; if (hostOk(m[0]) && inR(m[1]) && (!mKind || m[3] === mKind) && (!ts || matchAll(mHay(i), ts))) out.push(i); } return out; },
  terms: () => tM,
  count(n){ let tot = 0; for (const m of M) if (hostOk(m[0]) && inR(m[1])) tot++; $("c-moments").innerHTML = countTxt(n, tot, "moments"); },
  emptyText: () => "No moments match. Clear the search or widen the time range.",
  clear(keepRange){ qM.value = ""; tM = null; mKind = ""; $("m-kind").value = ""; momentsT.refilter(); if (!keepRange && !isFull()) setRange(FA, FB); },
  open: i => inspect("m", i, true)
});
qM.addEventListener("input", debounce(() => { tM = terms(qM.value); momentsT.refilter(); }, 60));

// ── raw events ───────────────────────────────────────────────────
const qE = $("q-events"); let tE = null, eKind = "", showDups = false;
const nDups = E.filter(e => e[7] >= 0).length;
if (nDups){ $("e-dups-w").hidden = false; $("e-dups-l").textContent = `Show copies (${fmtN(nDups)})`; }
$("e-dups").addEventListener("change", function(){ showDups = this.checked; eventsT.refilter(); });
(() => {
  const c = {}; E.forEach(e => { if (e[7] < 0) c[e[3]] = (c[e[3]] || 0) + 1; });
  const ks = Object.keys(c).sort((a, b) => c[b] - c[a] || (a < b ? -1 : 1));
  $("e-kind").innerHTML = '<option value="">All event types</option>' + ks.map(k => `<option value="${h(k)}">${h(k)} (${fmtN(c[k])})</option>`).join("");
  $("e-kind").addEventListener("change", function(){ eKind = this.value; eventsT.refilter(); });
})();
const summaryOf = e => e[9].slice(0, 4).map(kv => kv[0] + "=" + (kv[1].length > 40 ? kv[1].slice(0, 40) + "…" : kv[1])).join("  ");
const eventsT = new VTable({
  id: "t-events", minw: multi ? 1010 : 910, sortCol: 0,
  cols: [{label: "Time (UTC)", w: "minmax(140px,.8fr)", cls: "m", get: i => E[i][10], sort: i => E[i][0]},
    {label: "Event", w: "minmax(150px,.8fr)", get: i => E[i][3], sort: i => E[i][3]},
    ...(multi ? [{label: "Computer", w: "minmax(90px,.5fr)", get: i => hostName(E[i][2]), sort: i => hostName(E[i][2]).toLowerCase()}] : []),
    {label: "Description", w: "minmax(240px,2.4fr)", cls: "dim", get: i => E[i][4] || summaryOf(E[i]), tip: i => E[i][4] || summaryOf(E[i])},
    {label: "Event record ID", w: "112px", cls: "m r", r: true, get: i => E[i][6], sort: i => +E[i][6] || 0},
    {label: "Log", w: "minmax(100px,.6fr)", cls: "dim", get: i => shortFile(D.files[E[i][5]]), tip: i => D.files[E[i][5]], sort: i => shortFile(D.files[E[i][5]])}],
  rowCls: i => E[i][7] >= 0 ? " dup" : "",
  filter(){ const out = [], ts = tE; for (let i = 0; i < E.length; i++){ const e = E[i]; if (hostOk(e[2]) && inR(e[0]) && (showDups || e[7] < 0) && (!eKind || e[3] === eKind) && (!ts || matchAll(eHay(i), ts))) out.push(i); } return out; },
  terms: () => tE,
  count(n){ let tot = 0; for (const e of E) if (hostOk(e[2]) && inR(e[0]) && (showDups || e[7] < 0)) tot++; $("c-events").innerHTML = countTxt(n, tot, "events"); },
  emptyText: () => "No events match. The search looks in every field value.",
  clear(keepRange){ qE.value = ""; tE = null; eKind = ""; $("e-kind").value = ""; eventsT.refilter(); if (!keepRange && !isFull()) setRange(FA, FB); },
  open: i => inspect("e", i, true)
});
qE.addEventListener("input", debounce(() => { tE = terms(qE.value); eventsT.refilter(); }, 80));

let usedBy = null;
function uses(i){
  if (!usedBy){
    usedBy = {};
    P.forEach((p, k) => { [[13, "start"], [14, "end"]].forEach(([c, r]) => { const e = p[c]; if (e >= 0) (usedBy[e] = usedBy[e] || []).push(["p", k, r]); }); });
    M.forEach((m, k) => { if (m[6] >= 0) (usedBy[m[6]] = usedBy[m[6]] || []).push(["m", k]); });
  }
  return usedBy[i] || [];
}

// ── inspector ────────────────────────────────────────────────────
const insp = $("insp"); let lastFocus = null;
const kv = rows => `<dl class="kv">${rows.map(r => `<dt>${h(r[0])}</dt><dd${r[2] ? ' class="m"' : ""}>${h(r[1])}${r[3] ? `<span class="mean">${h(r[3])}</span>` : ""}</dd>`).join("")}</dl>`;
function eventText(e){
  const ev = E[e], s = [`${ev[3]}  record ${ev[6]}  ${ev[1]} UTC`]; if (ev[4]) s.push(ev[4]);
  for (const r of sysRows(ev)) s.push(`${r[0]}: ${r[1]}`); for (const r of ev[9]) s.push(`${r[0]}: ${r[1]}${r[2] ? "  (" + r[2] + ")" : ""}`);
  return s.join("\n");
}
function evCard(e, role){
  if (e < 0) return `<div class="evc"><div class="hd">${h(role)} · not proven by a single event</div></div>`;
  const ev = E[e]; let reading = ev[4];
  if (!reading){ const mo = uses(e).find(x => x[0] === "m"); if (mo) reading = M[mo[1]][3] + (M[mo[1]][4] ? ": " + M[mo[1]][4] : ""); }
  return `<div class="evc"><div class="hd"><b>${h(ev[3])}</b><span class="t">#${h(ev[6])} · ${h(ev[1])}</span><span class="sp">`
    + `<button class="btn icon ghost" type="button" data-copy="${e}" aria-label="Copy event" title="Copy event as text">${icon("copy")}</button>`
    + `<button class="btn icon ghost" type="button" data-goto="${e}" aria-label="Show in raw events" title="Show in raw events">${icon("list")}</button></span></div>`
    + `<div class="bd">${role ? `<div class="role">${h(role)}</div>` : ""}${reading ? `<p class="desc">${h(reading)}</p>` : ""}`
    + (ev[9].length ? `<div class="sub">Event data</div>${kv(ev[9].map(r => [r[0], r[1], 1, r[2]]))}` : "")
    + `<details class="sys"><summary>${icon("right")}System fields (${sysRows(ev).length})</summary>${kv(sysRows(ev).map(r => [r[0], r[1], 1]))}</details>`
    + (ev[7] >= 0 ? `<p class="dupnote">A copy of <a href="#event-${ev[7]}" data-ev="${ev[7]}">this event</a> from another copy of the log; counted once.</p>` : "")
    + `</div></div>`;
}
// How a period's start and end were measured, in plain words (module doc of
// evtx_tool.analysis.system_activity); the actual evidence follows below.
function howMeasured(p){
  const b = base(p[2]), k = stKey(p[2]), sb = withRec(p[10], p[13]), eb = withRec(p[11], p[14]);
  if (b === "On") return `On from when Windows started or woke up (${sb}) until it slept, went into standby or stopped (${eb}).`;
  if (k === "off" || k === "crash") return `${b} from when Windows stopped (${sb}) until it started again (${eb}). `
    + "Kernel-General 13 holds the exact moment the kernel stopped and Kernel-General 12 the exact moment it started; "
    + "EventLog 6006 / 6005 and Security 4609 / 4608 confirm a clean stop and start. "
    + (k === "crash" ? "This one ended without a clean shutdown (Kernel-Power 41 or EventLog 6008). " : "")
    + (p[5] != null && p[5] < 5 * 60e6 ? `Only ${fmtTotal(p[5])} passed between the stop and the start: a restart, not a time the computer was left switched off. ` : "")
    + "Who or what asked for a shutdown or restart is in Moments (User32 1074, \u201cShutdown or restart requested\u201d).";
  if (b === "Modern Standby") return `Modern Standby from Kernel-Power 506 (entering) to 507 (exiting): here ${sb} to ${eb}.`;
  if (k === "sleep" || k === "hib" || k === "low") return `${b}: Power-Troubleshooter 1 gives the exact sleep and wake times; Kernel-Power 42 marks going to sleep. `
    + `Here it started with ${sb} and ended with ${eb}. Kernel-Power 107 (\u201cresumed\u201d) is written with the clock from before the sleep and is never used as the wake time.`;
  if (p[1] === "Screen") return `Screen sessions come from Kernel-Power 566: each one gives the previous session's type and its length, as Windows measured it. Here ${sb} to ${eb}.`;
  if (p[1] === "Lock") return `Lock from Security 4800 / 4802 to 4801 / 4803 (or an unlock logon, type 7): here ${sb} to ${eb}.`;
  return `Started by ${sb}; ended by ${eb}.`;
}
function inspect(kind, i, fromTable){
  let head = "", body = "";
  if (kind === "p"){
    const p = P[i];
    head = `<h2><span class="sw st-${stKey(p[2])}" style="width:12px;height:12px;margin:0"></span>${h(p[2])}</h2><p>${h(p[1])} · ${h(hostName(p[0]))}</p>`;
    body = `<div class="big"><div><span>Start (UTC)</span><b>${h(p[15])}</b></div><div><span>End (UTC)</span><b>${h(p[16])}</b></div><div><span>Duration</span><b>${h(p[9])}</b></div></div>`
      + `<p class="how">${h(howMeasured(p))}</p>`
      + kv([["Started by", withRec(p[10], p[13])], ["Ended by", withRec(p[11], p[14])], ...(p[12] ? [["Notes", p[12]]] : [])])
      + `<h3>Evidence</h3>${evCard(p[13], "Starts this period")}${p[14] !== p[13] ? evCard(p[14], "Ends this period") : ""}`;
    markTl(["p", i]);
  } else if (kind === "m"){
    const m = M[i];
    head = `<h2>${h(m[3])}</h2><p>Moment · ${h(hostName(m[0]))}</p>`;
    body = `<div class="big"><div><span>Time (UTC)</span><b>${h(m[7])}</b></div></div>` + kv([["Details", m[4]], ["Evidence", withRec(m[5], m[6])]]) + `<h3>Evidence</h3>${evCard(m[6], "")}`;
    markTl(["m", i]);
  } else {
    const e = E[i], u = uses(i);
    head = `<h2>${h(e[3])}</h2><p>Raw event · ${h(hostName(e[2]))}</p>`;
    body = evCard(i, "") + "<h3>Used by</h3>" + (u.length ? '<div class="used">' + u.map(x => {
      if (x[0] === "p"){ const pp = P[x[1]]; return `<a href="#period-${x[1]}" data-pr="${x[1]}"><span class="sw st-${stKey(pp[2])}"></span>${x[2] === "start" ? "Start of " : "End of "}${h(pp[2])} · ${h(pp[6])}</a>`; }
      const mm = M[x[1]]; return `<a href="#moment-${x[1]}" data-mo="${x[1]}">${h(mm[3])} · ${h(mm[2])}</a>`;
    }).join("") + "</div>" : '<p style="color:var(--text-2);font-size:13px;margin:0">Read by the analysis but not cited by a period or moment.</p>');
  }
  $("insp-head").innerHTML = head; $("insp-body").innerHTML = body; $("insp-body").scrollTop = 0;
  if (!insp.classList.contains("on")) lastFocus = document.activeElement;
  insp.classList.add("on"); insp.setAttribute("aria-hidden", "false");
  try { history.replaceState(null, "", "#" + {p: "period-", m: "moment-", e: "event-"}[kind] + i); } catch(e){}
  if (!fromTable) $("insp-x").focus({preventScroll: true});
}
function closeInsp(){
  insp.classList.remove("on"); insp.setAttribute("aria-hidden", "true"); markTl(null);
  try { history.replaceState(null, "", location.pathname + location.search); } catch(e){}
  if (lastFocus && lastFocus.focus) lastFocus.focus({preventScroll: true});
}
$("insp-x").addEventListener("click", closeInsp);
$("insp-body").addEventListener("click", ev => {
  const t = ev.target.closest("[data-copy],[data-goto],[data-ev],[data-pr],[data-mo]"); if (!t) return;
  ev.preventDefault();
  if (t.hasAttribute("data-copy")) copy(eventText(+t.getAttribute("data-copy")));
  else if (t.hasAttribute("data-goto")){ const e = +t.getAttribute("data-goto"); if (E[e][7] >= 0 && !showDups){ showDups = true; $("e-dups").checked = true; eventsT.refilter(); } eventsT.reveal(e); inspect("e", e, true); }
  else if (t.hasAttribute("data-ev")) inspect("e", +t.getAttribute("data-ev"));
  else if (t.hasAttribute("data-pr")){ const p = +t.getAttribute("data-pr"); periodsT.reveal(p); inspect("p", p, true); }
  else if (t.hasAttribute("data-mo")){ const m = +t.getAttribute("data-mo"); momentsT.reveal(m); inspect("m", m, true); }
});

// ── keyboard, nav, print ─────────────────────────────────────────
[qP, qM, qE].forEach(q => q.addEventListener("keydown", ev => { if (ev.key === "Escape" && q.value){ ev.stopPropagation(); q.value = ""; q.dispatchEvent(new Event("input")); } }));
document.addEventListener("keydown", ev => {
  if (ev.key === "Escape" && insp.classList.contains("on")) return closeInsp();
  const tag = (ev.target.tagName || "").toLowerCase();
  if (ev.key === "/" && !["input", "select", "textarea"].includes(tag)){
    ev.preventDefault();
    const sec = [["events", qE], ["moments", qM], ["periods", qP]].find(x => $(x[0]).getBoundingClientRect().top < innerHeight / 2);
    const q = sec ? sec[1] : qP; q.focus(); q.select();
  }
});
(() => {
  const links = document.querySelectorAll(".nav a"); if (!("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) links.forEach(a => a.classList.toggle("on", a.getAttribute("href") === "#" + e.target.id)); }), {rootMargin: "-40% 0px -55% 0px"});
  document.querySelectorAll("main section").forEach(s => io.observe(s));
})();
const tables = [periodsT, momentsT, eventsT];
$("print").addEventListener("click", () => window.print());
addEventListener("beforeprint", () => tables.forEach(t => { t.full = true; t.paint(true); }));
addEventListener("afterprint", () => tables.forEach(t => { t.full = false; t.paint(true); }));

// ── hosts ────────────────────────────────────────────────────────
(() => {
  const s = $("host");
  if (!multi){ s.hidden = true; return; }
  s.innerHTML = '<option value="-1">All computers</option>' + D.hosts.map((_, i) => `<option value="${i}">${h(hostName(i))}</option>`).join("");
  s.addEventListener("change", () => { hostSel = +s.value; buildAgg(); brushRender(); calRender(); refreshRange(); });
})();

function refreshRange(){
  const t0 = performance.now();
  brushSel(R.a, R.b); calSel(); syncPresets();
  inFrom.value = toInput(R.a); inTo.value = toInput(R.b);
  $("chip").classList.toggle("on", !isFull()); $("chip-t").textContent = whenText(R.a, R.b).replace(/<[^>]+>/g, "").replace(/ · .*/, "");
  overview(); heatRender(); tlAll = false; tlRender();
  tables.forEach(t => t.refilter());
  let np = 0, nm = 0, ne = 0;
  for (const p of P) if (hostOk(p[0]) && pIn(p)) np++;
  for (const m of M) if (hostOk(m[0]) && inR(m[1])) nm++;
  for (const e of E) if (hostOk(e[2]) && inR(e[0]) && e[7] < 0) ne++;
  $("n-periods").textContent = fmtN(np); $("n-moments").textContent = fmtN(nm); $("n-events").textContent = fmtN(ne);
  (window.__ehPerf = window.__ehPerf || {}).range = performance.now() - t0;
}

const syncBar = () => root.style.setProperty("--bar-h", document.querySelector(".bar").offsetHeight + "px");
let resizeT; addEventListener("resize", () => { syncBar(); clearTimeout(resizeT); resizeT = setTimeout(brushRender, 120); });
syncBar();
const tb = performance.now();
buildAgg(); actsRender(); brushRender(); calRender(); refreshRange();
$("foot").innerHTML = `Generated by EventHawk ${h(D.meta.version)} on ${h(D.meta.generated)}. Times are UTC; tables show ${D.meta.digits ? D.meta.digits + " decimal places" : "whole seconds"} and the details panel shows exact values; durations are never rounded up. This file is self-contained and makes no network requests.`;
(window.__ehPerf = window.__ehPerf || {}).boot = performance.now() - tb;
(() => {
  const m = /^#(period|moment|event)-(\d+)$/.exec(location.hash); if (!m) return;
  const i = +m[2], k = {period: ["p", P, periodsT], moment: ["m", M, momentsT], event: ["e", E, eventsT]}[m[1]];
  if (i < k[1].length){ k[2].reveal(i); inspect(k[0], i, true); }
})();
})();
"""

TEMPLATE = (
    "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">\n"
    "<meta name=\"referrer\" content=\"no-referrer\">\n<meta name=\"generator\" content=\"EventHawk\">\n"
    "<title>__TITLE__</title>\n<link rel=\"icon\" href=\"__LOGO__\">\n<style>\n"
    ":root{" + _LIGHT + "}\n"
    ":root[data-theme=dark]{" + _DARK + "}\n"
    "@media (prefers-color-scheme:dark){:root:not([data-theme=light]){" + _DARK + "}}\n"
    + _CSS + "</style>\n</head>\n<body>" + _BODY
    + "<script type=\"application/json\" id=\"data\">__DATA__</script>\n<script>" + _JS + "</script>\n</body>\n</html>\n"
)
