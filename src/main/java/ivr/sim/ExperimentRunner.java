package ivr.sim;

import ivr.data.SeedData;
import ivr.model.Account;
import ivr.verify.VerificationService;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 端到端实验。同一批账户，分别让 真用户 / 多类攻击者 走完整流程，
 * 每次都从全新状态开始，并在 8 次换号来电内反复尝试。
 *
 * <p>核心指标不是“最终是否成功”，而是<b>要成功需要付出多少次来电</b>：
 * 如果一个攻击者平均要打 5 次才过一次，而每次都留下痕迹、且通过后仍不能立即改绑，
 * 这套流程在经济上就不划算。
 */
public final class ExperimentRunner {

    public record ScenarioResult(String label, int trials,
                                 int[] passedAtCall,   // index 1..N
                                 int neverPassed,
                                 int canaryCaught,
                                 int blockedByQuota,
                                 double avgCallsToPass) {
        int passes() {
            int s = 0;
            for (int i = 1; i < passedAtCall.length; i++) s += passedAtCall[i];
            return s;
        }
    }

    static final int MAX_CALLS = 8;

    public static void main(String[] args) {
        int trials = args.length > 0 ? Integer.parseInt(args[0]) : 500;
        List<Account> accounts = SeedData.accounts();

        System.out.println("=== 身份核验系统 · 端到端实验 ===");
        System.out.printf("账户数=%d  每场景试次=%d  每场景最多来电=%d%n%n",
                accounts.size(), trials, MAX_CALLS);

        List<ScenarioResult> results = new ArrayList<>();
        results.add(runGenuine(accounts, trials, 1.0));
        results.add(runGenuine(accounts, trials, 1.8));
        results.add(runGenuine(accounts, trials, 2.6));
        results.add(runAttacker(accounts, trials, Attacker.Strategy.BLIND_GUESS,
                "盲猜（无泄露库）", AttackerKnowledge.Template.NONE));
        results.add(runAttacker(accounts, trials, Attacker.Strategy.DUMP_ONLY,
                "仅PII库", AttackerKnowledge.Template.PII));
        results.add(runAttacker(accounts, trials, Attacker.Strategy.DUMP_ONLY,
                "PII+订单库", AttackerKnowledge.Template.PII_ORDERS));
        results.add(runAttacker(accounts, trials, Attacker.Strategy.ADAPTIVE,
                "PII+订单·自适应试探", AttackerKnowledge.Template.PII_ORDERS));
        results.add(runAttacker(accounts, trials, Attacker.Strategy.CANARY_EATER,
                "买了投毒库", AttackerKnowledge.Template.PII_ORDERS_CANARY));
        results.add(runAttacker(accounts, trials, Attacker.Strategy.DUMP_ONLY,
                "PII+订单+行为（极端）", AttackerKnowledge.Template.FULL));

        printTable(results);
        printAnalysis(results);
    }

    // ---------- 真用户 ----------
    static ScenarioResult runGenuine(List<Account> accounts, int trials) {
        return runGenuine(accounts, trials, 1.0);
    }

    static ScenarioResult runGenuine(List<Account> accounts, int trials, double slipAmp) {
        int[] passedAt = new int[MAX_CALLS + 1];
        int never = 0;
        GenuineUser user = new GenuineUser(42, slipAmp);
        String label = slipAmp <= 1.0 ? "真用户（标称记性）"
                : "真用户（记性差 %.1fx）".formatted(slipAmp);
        for (int t = 0; t < trials; t++) {
            Account a = accounts.get(t % accounts.size());
            VerificationService svc = freshService(accounts);
            boolean ok = false;
            for (int call = 1; call <= 3 && !ok; call++) {
                var s = svc.startCall(a.accountId(), a.registeredAniTail());
                if (s.quiz() == null) break;
                var ans = user.answer(s.quiz());
                var r = svc.submit(a.accountId(), s.quiz().quizId(), ans, a.registeredAniTail());
                if (r.passed()) { passedAt[call]++; ok = true; }
            }
            if (!ok) never++;
        }
        return new ScenarioResult(label, trials, passedAt, never, 0, 0, avgCalls(passedAt));
    }

    // ---------- 攻击者 ----------
    static ScenarioResult runAttacker(List<Account> accounts, int trials,
                                      Attacker.Strategy strategy, String label,
                                      AttackerKnowledge.Template template) {
        int[] passedAt = new int[MAX_CALLS + 1];
        int never = 0, canaryCaught = 0, blockedByQuota = 0;
        long sumCalls = 0;
        int passCount = 0;

        for (int t = 0; t < trials; t++) {
            Account a = accounts.get(t % accounts.size());
            VerificationService svc = freshService(accounts);
            AttackerKnowledge kb = AttackerKnowledge.of(template, a);
            Attacker attacker = new Attacker(strategy, kb, 1000L + t);

            boolean episodePassed = false;
            for (int call = 1; call <= MAX_CALLS; call++) {
                String ani = "att" + t + "-" + call;   // 每次换号
                var s = svc.startCall(a.accountId(), ani);
                if (s.quiz() == null) {                 // 配额/风险闸门已封
                    blockedByQuota++;
                    break;
                }
                var ans = attacker.answer(s.quiz().questions());
                var r = svc.submit(a.accountId(), s.quiz().quizId(), ans, ani);
                if (r.debug().stream().anyMatch(d -> d.contains("CANARY_HIT"))) canaryCaught++;

                if (r.passed()) {
                    episodePassed = true;
                    passedAt[call]++;
                    sumCalls += call;
                    passCount++;
                    break;
                }
                attacker.observeFailure(s.quiz().questions(), ans);
            }
            if (!episodePassed) never++;
        }
        double avg = passCount == 0 ? Double.NaN : (double) sumCalls / passCount;
        return new ScenarioResult(label, trials, passedAt, never, canaryCaught,
                blockedByQuota, avg);
    }

    static VerificationService freshService(List<Account> accounts) {
        VerificationService svc = new VerificationService();
        accounts.forEach(svc::register);
        return svc;
    }

    private static double avgCalls(int[] passedAt) {
        long sum = 0; int n = 0;
        for (int i = 1; i < passedAt.length; i++) { sum += (long) passedAt[i] * i; n += passedAt[i]; }
        return n == 0 ? Double.NaN : (double) sum / n;
    }

    private static void printTable(List<ScenarioResult> results) {
        System.out.printf("%-22s %7s %8s %8s %8s %8s %9s%n",
                "场景", "试次", "通过率", "1次内", "2-3次内", "全未过", "被配额封");
        System.out.println("-".repeat(80));
        for (ScenarioResult r : results) {
            int p1 = r.passedAtCall()[1];
            int p23 = r.passedAtCall()[2] + r.passedAtCall()[3];
            double rate = 100.0 * r.passes() / r.trials();
            System.out.printf("%-22s %7d %7.1f%% %8d %8d %8d %9d%n",
                    r.label(), r.trials(), rate, p1, p23, r.neverPassed(), r.blockedByQuota());
        }
        System.out.println();
    }

    private static void printAnalysis(List<ScenarioResult> results) {
        ScenarioResult genuine = results.get(0);
        double genuineRate = 100.0 * genuine.passes() / genuine.trials();
        ScenarioResult forgetful = results.get(2);
        double forgetfulRate = 100.0 * forgetful.passes() / forgetful.trials();

        System.out.println("=== 结论 ===");
        System.out.printf("真用户（标称）一次通过率 %.1f%%，3 次内 %.1f%%%n",
                100.0 * genuine.passedAtCall()[1] / genuine.trials(), genuineRate);
        System.out.printf("真用户（记性差 2.6x）3 次内通过率 %.1f%%  ← 不刁难用户的底线%n",
                forgetfulRate);
        System.out.println();

        Map<String, Double> rates = new LinkedHashMap<>();
        for (int i = 3; i < results.size(); i++) {
            ScenarioResult r = results.get(i);
            rates.put(r.label(), 100.0 * r.passes() / r.trials());
        }

        System.out.println("攻击者通过率（越低越好）：");
        rates.forEach((k, v) -> System.out.printf("  %-22s %5.1f%%%n", k, v));
        System.out.println();

        System.out.println("关键解读：");
        System.out.println("  · 只有 PII/订单库的攻击者，通过率应接近盲猜——");
        System.out.println("    因为系统几乎不把泄露类事实当放行依据。");
        System.out.println("  · 投毒题一旦命中，直接转人工，一次即封。");
        System.out.println("  · 同一账户每 epoch 最多 3 份问卷，换号不能刷新配额，");
        System.out.println("    因此“多打几次多抽奖”的收益被配额闸门吃光。");
        System.out.println("  · 极端场景（连行为数据都泄露）无法靠问答区分，");
        System.out.println("    这正是最后一道闸门——冷却期 + 全渠道通知——存在的原因。");
    }
}
