package ivr.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ivr.data.SeedData;
import ivr.model.Account;
import ivr.model.AccountState;
import ivr.model.Option;
import ivr.model.Question;
import ivr.model.Quiz;
import ivr.verify.VerificationService;
import ivr.sim.Attacker;
import ivr.sim.AttackerKnowledge;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 坐席控制台（零依赖，JDK 内置 HttpServer）。
 *
 * <p><b>安全边界在序列化层。</b>内部的 {@link Question} 带着正确答案，
 * 但对外 JSON 只输出字段白名单——答案永远不出这个进程。
 */
public final class ApiServer {

    private final VerificationService svc = new VerificationService();

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        new ApiServer().start(port);
    }

    public void start(int port) throws IOException {
        SeedData.accounts().forEach(svc::register);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", this::handleIndex);
        server.createContext("/api/accounts", this::handleAccounts);
        server.createContext("/api/call", this::handleCall);
        server.createContext("/api/submit", this::handleSubmit);
        server.createContext("/api/state", this::handleState);
        server.createContext("/api/simulate", this::handleSimulate);
        server.setExecutor(null);
        server.start();
        System.out.println("坐席控制台: http://localhost:" + port);
        System.out.println("（内部演示用；生产需接入鉴权、TLS、真实 ANI 与通知服务）");
    }

    private void handleIndex(HttpExchange ex) throws IOException {
        if (!"/".equals(ex.getRequestURI().getPath())) { notFound(ex); return; }
        send(ex, 200, "text/html; charset=utf-8", CONSOLE_HTML);
    }

    private void handleAccounts(HttpExchange ex) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Account a : svc.allAccounts()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("accountId", a.accountId());
            m.put("displayName", a.displayName());
            m.put("phoneMasked", a.phoneMasked());
            m.put("aniTail", a.registeredAniTail());
            AccountState st = svc.state(a.accountId());
            m.put("riskLogOdds", round(st.riskLogOdds()));
            m.put("bitsUsed", round(st.totalExposedBits()));
            m.put("quizzesThisEpoch", st.quizzesThisEpoch());
            out.add(m);
        }
        sendJson(ex, out);
    }

    /** 开始一通来电。参数：accountId, ani（可空） */
    private void handleCall(HttpExchange ex) throws IOException {
        Map<String, String> p = query(ex);
        String accountId = p.getOrDefault("accountId", "");
        String ani = p.getOrDefault("ani", "").isBlank() ? "unknown" : p.get("ani");

        var session = svc.startCall(accountId, ani);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sessionId", session.sessionId());
        m.put("script", session.deliveryScript());
        m.put("hasQuiz", session.quiz() != null);
        m.put("quiz", session.quiz() == null ? null : publicQuiz(session.quiz()));
        sendJson(ex, m);
    }

    /** 提交作答。body: quizId, accountId, ani, answers[factId]=optId|__decline__ */
    private void handleSubmit(HttpExchange ex) throws IOException {
        Map<String, String> p = parseBody(new String(ex.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8));
        String accountId = p.get("accountId");
        String quizId = p.get("quizId");
        String ani = p.getOrDefault("ani", "unknown");

        Map<String, Set<String>> answers = new HashMap<>();
        for (Map.Entry<String, String> e : p.entrySet()) {
            if (!e.getKey().startsWith("ans.")) continue;
            String fact = e.getKey().substring(4);
            String opt = e.getValue();
            answers.put(fact, "__decline__".equals(opt) || opt.isBlank()
                    ? Set.of() : Set.of(opt));
        }

        var r = svc.submit(accountId, quizId, answers, ani);
        Map<String, Object> m = new LinkedHashMap<>();
        // 对外只给这两样：一句恒定话术 + 通过/未通过。
        m.put("script", r.script());
        m.put("passed", r.passed());
        sendJson(ex, m);
    }

    /** 内部状态（演示用；生产必须走单独鉴权通道，且不对坐席开放）。 */
    private void handleState(HttpExchange ex) throws IOException {
        Map<String, String> p = query(ex);
        String accountId = p.getOrDefault("accountId", "");
        AccountState st = svc.state(accountId);
        Map<String, Object> m = new LinkedHashMap<>();
        if (st != null) {
            m.put("riskLogOdds", round(st.riskLogOdds()));
            m.put("totalExposedBits", round(st.totalExposedBits()));
            m.put("bitsRemaining", round(Math.max(0,
                    ivr.risk.RiskEngine.EXPOSURE_BUDGET_BITS - st.totalExposedBits())));
            m.put("quizzesThisEpoch", st.quizzesThisEpoch());
            m.put("escalationCount", st.escalationCount());
            List<Map<String, Object>> calls = new ArrayList<>();
            for (var c : st.calls()) {
                Map<String, Object> cm = new LinkedHashMap<>();
                cm.put("aniTail", c.aniTail());
                cm.put("outcome", c.outcome());
                cm.put("bits", round(c.bitsExposed()));
                calls.add(cm);
            }
            m.put("calls", calls);
        }
        sendJson(ex, m);
    }

    /**
     * 演示：让一个“持泄露库的攻击者”自动作答，便于观察系统如何回应。
     * 参数：accountId, template(NONE|PII|PII_ORDERS|FULL), calls(次数)
     */
    private void handleSimulate(HttpExchange ex) throws IOException {
        Map<String, String> p = query(ex);
        String accountId = p.getOrDefault("accountId", "");
        String tplName = p.getOrDefault("template", "PII_ORDERS");
        int calls = Math.min(8, Math.max(1, Integer.parseInt(p.getOrDefault("calls", "3"))));

        Account acct = svc.account(accountId);
        if (acct == null) { sendJson(ex, Map.of("error", "unknown account")); return; }

        var template = AttackerKnowledge.Template.valueOf(tplName);
        var kb = AttackerKnowledge.of(template, acct);
        var attacker = new Attacker(Attacker.Strategy.ADAPTIVE, kb, 12345L);

        List<Map<String, Object>> log = new ArrayList<>();
        for (int call = 1; call <= calls; call++) {
            String ani = "sim-" + call;
            var s = svc.startCall(accountId, ani);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("call", call);
            if (s.quiz() == null) {
                row.put("result", "不出题（风控闸门已封）");
                log.add(row);
                break;
            }
            var ans = attacker.answer(s.quiz().questions());
            var r = svc.submit(accountId, s.quiz().quizId(), ans, ani);
            row.put("questions", s.quiz().questions().size());
            row.put("passed", r.passed());
            row.put("script", r.script());
            log.add(row);
            if (r.passed()) break;
        }
        sendJson(ex, Map.of("log", log));
    }

    // ---------- 序列化白名单：绝不输出 correctOptionIds ----------
    private Map<String, Object> publicQuiz(Quiz quiz) {
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("quizId", quiz.quizId());
        q.put("accountId", quiz.accountId());
        List<Map<String, Object>> qs = new ArrayList<>();
        for (Question question : quiz.questions()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("factId", question.factId());
            item.put("prompt", question.prompt());
            item.put("freeText", question.isFreeText());
            List<Map<String, String>> opts = new ArrayList<>();
            for (Option o : question.options()) {
                opts.add(Map.of("id", o.id(), "label", o.label()));
            }
            item.put("options", opts);
            // 注意：这里没有 correctOptionIds。
            qs.add(item);
        }
        q.put("questions", qs);
        return q;
    }

    // ---------- 小工具 ----------
    private static Map<String, String> query(HttpExchange ex) {
        return parseBody(ex.getRequestURI().getRawQuery());
    }

    private static Map<String, String> parseBody(String s) {
        Map<String, String> m = new HashMap<>();
        if (s == null || s.isBlank()) return m;
        for (String pair : s.split("&")) {
            int i = pair.indexOf('=');
            if (i < 0) continue;
            String k = URLDecoder.decode(pair.substring(0, i), StandardCharsets.UTF_8);
            String v = URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
            m.put(k, v);
        }
        return m;
    }

    private static double round(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    private void sendJson(HttpExchange ex, Object o) throws IOException {
        send(ex, 200, "application/json; charset=utf-8", json(o));
    }

    private void notFound(HttpExchange ex) throws IOException {
        send(ex, 404, "text/plain; charset=utf-8", "not found");
    }

    private void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** 极简 JSON 序列化（避免引入依赖）。 */
    @SuppressWarnings("unchecked")
    static String json(Object o) {
        if (o == null) return "null";
        if (o instanceof String s) return quote(s);
        if (o instanceof Boolean b) return b.toString();
        if (o instanceof Number n) return n.toString();
        if (o instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(quote(String.valueOf(e.getKey()))).append(':').append(json(e.getValue()));
            }
            return sb.append('}').toString();
        }
        if (o instanceof Iterable<?> it) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object v : it) {
                if (!first) sb.append(',');
                first = false;
                sb.append(json(v));
            }
            return sb.append(']').toString();
        }
        return quote(o.toString());
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    private static final String CONSOLE_HTML = """
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>坐席身份核验控制台</title>
<style>
:root{--bg:#0f1216;--panel:#171c23;--line:#2a323d;--fg:#e6edf3;--dim:#8b98a8;--accent:#4aa8ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,"PingFang SC",sans-serif}
header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0;font-weight:600}
.tag{color:var(--dim);font-size:12px}
main{display:grid;grid-template-columns:300px 1fr;gap:16px;padding:16px;align-items:start}
@media(max-width:820px){main{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.acct{padding:10px;border:1px solid var(--line);border-radius:8px;margin-bottom:8px;cursor:pointer}
.acct:hover{border-color:var(--accent)}
.acct.sel{border-color:var(--accent);background:#1b2531}
.acct b{display:block}
.dim{color:var(--dim);font-size:12px}
button{background:var(--accent);color:#001;border:0;border-radius:7px;padding:8px 14px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
button:disabled{opacity:.4;cursor:default}
.q{border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:10px}
.q h3{margin:0 0 10px;font-size:14px;font-weight:600}
.opt{display:flex;gap:8px;align-items:center;padding:5px 0;cursor:pointer}
input[type=text]{width:100%;background:#0d1117;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:7px 10px}
.script{background:#0d1117;border-left:3px solid var(--accent);padding:10px 12px;border-radius:6px;white-space:pre-wrap;margin:10px 0}
.script.bad{border-left-color:var(--bad)}
.script.ok{border-left-color:var(--ok)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:500}
.risk{font-variant-numeric:tabular-nums}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:10px}
.warnbox{border:1px solid var(--warn);color:var(--warn);border-radius:8px;padding:8px 12px;font-size:12px;margin-bottom:12px}
</style></head><body>
<header><h1>坐席身份核验控制台</h1>
<span class="tag">盲答整批 · 单一话术 · 跨来电聚合</span></header>
<main>
<div class="panel">
  <div class="tag" style="margin-bottom:8px">选择账户</div>
  <div id="accounts"></div>
</div>
<div>
  <div class="panel" id="stage">
    <div class="dim">请先选择一个账户。</div>
  </div>
  <div class="panel" style="margin-top:16px">
    <div class="tag" style="margin-bottom:8px">内部风控视图（不对来电者可见）</div>
    <div id="internal" class="dim">—</div>
  </div>
</div>
</main>
<script>
let accounts=[],cur=null,quiz=null;

async function load(){
  accounts=await (await fetch('/api/accounts')).json();
  const el=document.getElementById('accounts');
  el.innerHTML=accounts.map(a=>`
    <div class="acct ${cur&&cur.accountId===a.accountId?'sel':''}" onclick="pick('${a.accountId}')">
      <b>${a.displayName} <span class="dim">${a.accountId}</span></b>
      <span class="dim">${a.phoneMasked} · 风险 ${a.riskLogOdds} · 已用 ${a.bitsUsed}bit</span>
    </div>`).join('');
}

async function pick(id){
  cur=accounts.find(a=>a.accountId===id);
  quiz=null;
  await load();
  renderStart();
  refreshInternal();
}

function renderStart(){
  document.getElementById('stage').innerHTML=`
    <h3 style="margin:0 0 6px">${cur.displayName} <span class="dim">${cur.accountId}</span></h3>
    <div class="dim">来电号码尾号：<input id="ani" type="text" value="${cur.aniTail}" style="width:120px;display:inline-block"></div>
    <div class="row">
      <button onclick="startCall()">开始核验</button>
      <button class="ghost" onclick="simulate('PII_ORDERS')">模拟：持泄露库攻击者</button>
      <button class="ghost" onclick="simulate('FULL')">模拟：全量数据攻击者</button>
    </div>
    <div id="simlog" style="margin-top:12px"></div>`;
}

async function startCall(){
  const ani=document.getElementById('ani').value;
  const r=await (await fetch(`/api/call?accountId=${cur.accountId}&ani=${encodeURIComponent(ani)}`)).json();
  if(!r.hasQuiz){
    document.getElementById('stage').innerHTML=`<div class="script bad">${r.script}</div>
      <div class="row"><button class="ghost" onclick="renderStart()">返回</button></div>`;
    return;
  }
  quiz=r.quiz;
  const qs=quiz.questions.map(q=>`
    <div class="q">
      <h3>${q.prompt}</h3>
      ${q.freeText
        ? `<input type="text" id="ft_${q.factId}" placeholder="请让来电者口述；不确定请留空">
           <div class="opt"><input type="checkbox" id="decl_${q.factId}"> 来电者表示记不清（拒答）</div>`
        : q.options.map(o=>`<label class="opt"><input type="radio" name="${q.factId}" value="${o.id}"> ${o.label}</label>`).join('')
          + `<div class="opt"><input type="radio" name="${q.factId}" value="__decline__"> 记不清 / 拒答</div>`}
    </div>`).join('');
  document.getElementById('stage').innerHTML=`
    <div class="script">${r.script}</div>
    ${qs}
    <div class="row"><button onclick="submitQuiz()">提交核对</button>
    <button class="ghost" onclick="renderStart()">取消</button></div>`;
}

async function submitQuiz(){
  const body=new URLSearchParams();
  body.set('accountId',cur.accountId); body.set('quizId',quiz.quizId);
  body.set('ani',document.getElementById('ani')?.value||cur.aniTail);
  for(const q of quiz.questions){
    let v='__decline__';
    if(q.freeText){
      const t=(document.getElementById('ft_'+q.factId).value||'').trim();
      if(t) v=t;
    } else {
      const sel=document.querySelector(`input[name="${q.factId}"]:checked`);
      if(sel) v=sel.value;
    }
    body.set('ans.'+q.factId, v);
  }
  const r=await (await fetch('/api/submit',{method:'POST',body})).json();
  document.getElementById('stage').innerHTML=`
    <div class="script ${r.passed?'ok':'bad'}">${r.script}</div>
    <div class="row"><button class="ghost" onclick="renderStart()">结束通话</button></div>`;
  await refreshInternal();
  load();
}

async function simulate(template){
  const r=await (await fetch(`/api/simulate?accountId=${cur.accountId}&template=${template}&calls=6`)).json();
  const rows=(r.log||[]).map(x=>`<tr><td>${x.call}</td><td>${x.questions??'—'}</td>
    <td>${x.passed===undefined?'—':(x.passed?'<span style="color:var(--ok)">通过</span>':'未通过')}</td>
    <td class="dim">${x.script?x.script.slice(0,42)+'…':x.result}</td></tr>`).join('');
  document.getElementById('simlog').innerHTML=`
    <table><tr><th>来电</th><th>题数</th><th>结果</th><th>对外话术</th></tr>${rows}</table>`;
  await refreshInternal(); load();
}

async function refreshInternal(){
  const s=await (await fetch(`/api/state?accountId=${cur.accountId}`)).json();
  const calls=(s.calls||[]).slice(-6).map(c=>`<tr><td>${c.aniTail}</td><td>${c.outcome}</td><td>${c.bits}</td></tr>`).join('');
  document.getElementById('internal').innerHTML=`
    <div class="warnbox">此视图仅供风控与审计，绝不可回传给坐席或来电者。</div>
    <div class="row" style="margin-top:0">
      <span>风险 <b class="risk">${s.riskLogOdds??0}</b></span>
      <span>累计暴露 <b class="risk">${s.totalExposedBits??0}</b> bit</span>
      <span>本 epoch 问卷 <b>${s.quizzesThisEpoch??0}</b>/3</span>
    </div>
    <table style="margin-top:8px"><tr><th>号码尾号</th><th>结果</th><th>暴露bit</th></tr>${calls}</table>`;
}
load();
</script></body></html>
""";
}
