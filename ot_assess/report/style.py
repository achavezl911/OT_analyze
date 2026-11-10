"""Hoja de estilo del reporte HTML."""
from __future__ import annotations

HTML_CSS = """
:root{
  --tinta:#15202b; --suave:#5b6b7c; --linea:#dde3ea; --fondo:#ffffff;
  --panel:#f6f8fa; --acento:#17486b; --acento2:#2d6f9e;
  --critica:#8b1a1a; --alta:#b4530a; --media:#8a6d00; --baja:#4a6b52;
  --critica-bg:#fdecea; --alta-bg:#fdf1e3; --media-bg:#fdf8e1; --baja-bg:#eef4ef;
}
*{box-sizing:border-box}
body{margin:0;background:var(--fondo);color:var(--tinta);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;}
.wrap{max-width:1180px;margin:0 auto;padding:0 32px 72px}
header.port{background:var(--acento);color:#fff;padding:44px 32px 36px;margin-bottom:34px}
header.port .inner{max-width:1180px;margin:0 auto}
header.port h1{margin:0 0 6px;font-size:28px;font-weight:650;letter-spacing:-.2px}
header.port p{margin:0;color:#cfe0ee;font-size:14.5px}
h2{font-size:20px;margin:44px 0 6px;padding-bottom:9px;border-bottom:2px solid var(--acento);
  font-weight:640;letter-spacing:-.2px}
h3{font-size:16px;margin:28px 0 8px;font-weight:620}
.diagrama{border:1px solid var(--linea);border-radius:6px;overflow-x:auto;margin:10px 0 6px;background:#fff}
.diagrama svg{display:block;max-width:100%;height:auto}
p.lead{color:var(--suave);margin:8px 0 18px;max-width:72ch}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0 8px}
.kpi{flex:1 1 140px;background:var(--panel);border:1px solid var(--linea);
  border-radius:8px;padding:14px 16px}
.kpi .n{font-size:26px;font-weight:660;line-height:1.1;font-variant-numeric:tabular-nums}
.kpi .l{font-size:12px;color:var(--suave);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.tbl{overflow-x:auto;margin:14px 0 8px;border:1px solid var(--linea);border-radius:7px}
.tbl table{margin:0;border-radius:7px}
table{border-collapse:collapse;width:100%;margin:14px 0 8px;font-size:13.5px}
th{background:var(--panel);text-align:left;font-weight:620;font-size:12px;
  text-transform:uppercase;letter-spacing:.4px;color:var(--suave);
  padding:9px 10px;border-bottom:2px solid var(--linea);white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid var(--linea);vertical-align:top}
tbody tr:nth-child(even){background:#fbfcfd}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.tag{display:inline-block;padding:1.5px 8px;border-radius:11px;font-size:11.5px;
  font-weight:620;white-space:nowrap}
.t-critica{background:var(--critica-bg);color:var(--critica)}
.t-alta{background:var(--alta-bg);color:var(--alta)}
.t-media{background:var(--media-bg);color:var(--media)}
.t-baja{background:var(--baja-bg);color:var(--baja)}
.t-info{background:#eef2f6;color:var(--suave)}
.id-hallazgo{font:600 11px monospace;color:var(--suave);margin-left:6px}
.radar{margin:12px 0;overflow-x:auto}.radar svg{max-width:100%;height:auto}
.mapa-calor td{text-align:center;font-weight:700;color:#111}
.mc-bajo{background:#92D050}.mc-medio{background:#FFE699}.mc-alto{background:#F4B183}.mc-muy-alto{background:#FF5050}
.cruza{color:var(--critica);font-weight:620}
.finding{border:1px solid var(--linea);border-left:4px solid var(--linea);
  border-radius:7px;padding:16px 20px;margin:16px 0;background:#fff;break-inside:avoid}
.finding.s-alta{border-left-color:var(--critica)}
.finding.s-media{border-left-color:var(--alta)}
.finding.s-baja{border-left-color:var(--media)}
.finding.s-informativa{border-left-color:#9fb0c0}
.finding h4{margin:0 0 4px;font-size:15.5px;font-weight:640}
.finding .meta{font-size:12px;color:var(--suave);margin-bottom:10px}
.finding .ev{background:var(--panel);border:1px solid var(--linea);border-radius:6px;
  padding:10px 12px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
  white-space:pre-wrap;word-break:break-word;margin:10px 0;max-height:280px;overflow:auto}
.finding dl{margin:8px 0 0}
.finding dt{font-weight:620;font-size:13px;margin-top:8px}
.finding dd{margin:2px 0 0;color:#30404f;font-size:13.5px}
.grid-matrix{overflow-x:auto;margin:14px 0}
.grid-matrix table{font-size:11.5px;width:auto}
.grid-matrix th.v{writing-mode:vertical-rl;transform:rotate(180deg);
  height:130px;padding:6px 3px;vertical-align:bottom}
.grid-matrix td{text-align:center;padding:5px 7px;min-width:26px}
.grid-matrix td.on{background:#dcebf5;font-weight:620;color:var(--acento)}
.grid-matrix td.ctl{background:var(--critica-bg);color:var(--critica);font-weight:680}
.grid-matrix th.row{text-align:left;white-space:nowrap;background:var(--panel);
  position:sticky;left:0;text-transform:none;font-size:11.5px}
.nota{background:var(--panel);border-left:3px solid var(--acento2);padding:11px 15px;
  margin:14px 0;font-size:13.5px;color:#30404f;border-radius:0 6px 6px 0}
ul.q{margin:10px 0;padding-left:22px}
ul.q li{margin:7px 0;max-width:80ch}
footer{margin-top:56px;padding-top:18px;border-top:1px solid var(--linea);
  color:var(--suave);font-size:12px}
@page{size:A4 landscape;margin:12mm}
@media print{
.diagrama{overflow:visible;break-inside:avoid}
  body{font-size:9pt}
  .tbl{overflow:visible;border:none}
  table{font-size:8.5pt} th{font-size:7.5pt} .finding .ev{font-size:8pt}
  header.port{background:var(--acento) !important;-webkit-print-color-adjust:exact;
    print-color-adjust:exact}
  .wrap{max-width:none;padding:0 10mm}
  h2{break-after:avoid} table{break-inside:auto} tr{break-inside:avoid}
  .finding{break-inside:avoid} .ev{max-height:none;overflow:visible}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""
