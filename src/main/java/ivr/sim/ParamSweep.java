package ivr.sim;

import ivr.data.SeedData;
import ivr.model.Account;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 参数扫描：把“出题与计分规则”当作可搜索的空间，输出
 * 真用户通过率 × 攻击者通过率 的权衡曲线。
 *
 * <p>我们不是在找一个“神奇数字”，而是在验证一个形状：
 * <b>随着诱饵数/题数上升，攻击者通过率应单调下降，而真用户通过率不应跟着崩。</b>
 * 如果真用户先崩，说明规则在刁难人；如果攻击者不降，说明加题只是加成本没加安全。
 *
 * <p>用法：{@code java ivr.sim.ParamSweep}
 */
public final class ParamSweep {

    public static void main(String[] args) {
        int trials = args.length > 0 ? Integer.parseInt(args[0]) : 300;
        List<Account> accounts = SeedData.accounts();

        System.out.println("=== 参数扫描：题数 × 放行门槛 ===");
        System.out.println("（真用户通过率 / 已知 PII+订单 攻击者通过率）");
        System.out.println("注：门槛在 0.9~1.7 区间是“松弛区”——5 题卷的加权得分远高于门槛，");
        System.out.println("    真正起作用的区间在 2.5 以上，故上限扫到 3.2。");
        System.out.printf("%-8s", "题数\\门槛");
        double[] thresholds = {0.9, 2.0, 2.6, 3.2};
        for (double t : thresholds) System.out.printf("%-16s", "mw=" + t);
        System.out.println();
        System.out.println("-".repeat(76));

        for (int size : new int[]{3, 4, 5, 6}) {
            System.setProperty("ivr.quizSize", String.valueOf(size));
            System.out.printf("%-8d", size);
            for (double mw : thresholds) {
                System.setProperty("ivr.minCorrectWeight", String.valueOf(mw));
                double g = rate(ExperimentRunner.runGenuine(accounts, trials));
                double a = rate(ExperimentRunner.runAttacker(accounts, trials,
                        Attacker.Strategy.ADAPTIVE, "x", AttackerKnowledge.Template.PII_ORDERS));
                System.out.printf("%-16s", "%.0f%%/%.1f%%".formatted(g, a));
            }
            System.out.println();
        }

        System.setProperty("ivr.quizSize", "5");
        System.setProperty("ivr.minCorrectWeight", "1.10");

        System.out.println();
        System.out.println("=== 参数扫描：诱饵数 × 通过率（题数=5, mw=1.1） ===");
        System.out.printf("%-8s %-14s %-18s %-16s%n",
                "诱饵数", "真用户通过", "PII+订单攻击", "买了投毒库");
        System.out.println("-".repeat(58));
        for (int decoys : new int[]{3, 4, 5, 7}) {
            System.setProperty("ivr.decoys", String.valueOf(decoys));
            double g = rate(ExperimentRunner.runGenuine(accounts, trials));
            double a1 = rate(ExperimentRunner.runAttacker(accounts, trials,
                    Attacker.Strategy.ADAPTIVE, "x", AttackerKnowledge.Template.PII_ORDERS));
            double a3 = rate(ExperimentRunner.runAttacker(accounts, trials,
                    Attacker.Strategy.CANARY_EATER, "x", AttackerKnowledge.Template.PII_ORDERS_CANARY));
            System.out.printf(Locale.ROOT, "%-8d %-14s %-18s %-16s%n",
                    decoys, pct(g), pct(a1), pct(a3));
        }
        System.setProperty("ivr.decoys", "4");

        System.out.println();
        System.out.println("解读：");
        System.out.println("  1) 题数↑：真用户通过率随之上升（可拒答的空间更大），");
        System.out.println("     同时攻击者猜中全部所需题目的概率按 (1/n)^k 下降。存在一个双赢区间。");
        System.out.println("  2) 诱饵数↑：攻击者猜中率按 1/(1+诱饵数) 的幂下降；");
        System.out.println("     真用户因“不确定就跳过”几乎不受影响。");
        System.out.println("  3) 门槛只能筛掉“部分知情”攻击者。若行为数据也全数泄露，");
        System.out.println("     任何问答都无法区分——这是问答机制的固有上限，不是调参能解决的。");
        System.out.println("     对付它只能靠最后一道闸门：通过后进入 24h 冷却 + 全渠道通知。");
    }

    private static double rate(ExperimentRunner.ScenarioResult r) {
        return 100.0 * r.passes() / r.trials();
    }

    private static String pct(double v) {
        return "%.1f%%".formatted(v);
    }
}
