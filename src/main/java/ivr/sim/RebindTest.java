package ivr.sim;

import ivr.data.SeedData;
import ivr.model.Account;
import ivr.verify.VerificationService;

import java.util.List;

/**
 * 端到端夺取测试：衡量攻击者最终能不能<b>真正把手机改绑掉</b>，
 * 而不只是“问答通过”。
 *
 * <p>这是本系统价值主张的最终检验：
 * 问答通过 ≠ operation succeeds。通过后仍要过 24h 冷却 + 原机主全渠道通知。
 * 因此我们要看的是：
 * <ul>
 *   <li>问答层通过率（已由 {@link ExperimentRunner} 覆盖）；</li>
 *   <li>“问答通过”到“改绑成功”之间被冷却挡掉的比率；</li>
 *   <li>原机主收到告警的比率（本模型里等价于冷却生效）。</li>
 * </ul>
 */
public final class RebindTest {

    public static void main(String[] args) {
        int trials = args.length > 0 ? Integer.parseInt(args[0]) : 500;
        List<Account> accounts = SeedData.accounts();

        System.out.println("=== 端到端：攻击者最终能否完成改绑 ===");
        System.out.println("（问答通过后还有 24h 冷却 + 原渠道告警）");
        System.out.println();

        runCase(accounts, trials, "全量数据（极端）", Attacker.Strategy.ADAPTIVE,
                AttackerKnowledge.Template.FULL, 0);
        runCase(accounts, trials, "全量数据 + 等过冷却", Attacker.Strategy.ADAPTIVE,
                AttackerKnowledge.Template.FULL, VerificationService.REBIND_COOLDOWN_MILLIS + 1);
    }

    private static void runCase(List<Account> accounts, int trials, String label,
                                Attacker.Strategy strategy, AttackerKnowledge.Template template,
                                long waitMillis) {
        int quizPass = 0, rebindOk = 0, blockedByCooldown = 0, noQuiz = 0;

        for (int t = 0; t < trials; t++) {
            Account a = accounts.get(t % accounts.size());
            VerificationService svc = new VerificationService();
            accounts.forEach(svc::register);

            AttackerKnowledge kb = AttackerKnowledge.of(template, a);
            Attacker attacker = new Attacker(strategy, kb, 9000L + t);

            var s = svc.startCall(a.accountId(), "x" + t);
            if (s.quiz() == null) { noQuiz++; continue; }

            var ans = attacker.answer(s.quiz().questions());
            var r = svc.submit(a.accountId(), s.quiz().quizId(), ans, "x" + t);
            if (!r.passed()) continue;
            quizPass++;

            // 想立刻改绑 → 必须被冷却挡住。
            long now = System.currentTimeMillis();
            var immediate = svc.attemptRebind(a.accountId(), now);
            if (!immediate.allowed() && "cooldown".equals(immediate.reason())) blockedByCooldown++;

            // 等到冷却之后（模拟攻击者蹲守）。
            if (waitMillis > 0) {
                var later = svc.attemptRebind(a.accountId(), now + waitMillis);
                if (later.allowed()) rebindOk++;
            }
        }

        System.out.printf("%-24s 试次=%d 出题=%d 问答通过=%d 立即改绑被挡=%d 冷却后改绑成功=%d%n",
                label, trials, trials - noQuiz, quizPass, blockedByCooldown, rebindOk);
    }
}
