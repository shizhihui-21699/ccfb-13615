package ivr.qa;

import ivr.model.Question;

import java.text.Normalizer;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 逐题似然比评分。
 *
 * <p>核心思想：一道题的价值不是“答对了没有”，而是
 * <em>真用户的作答分布</em>与<em>攻击者的作答分布</em>之间的差异。
 * 答对本身常常没有信息量——如果答案就在泄露库里，攻击者也会答对。
 * 真正有信息量的是那些“真用户容易答对、攻击者不容易”的答案。
 *
 * <p>攻击者正确率显式建模为：
 * <pre>
 *   P(correct | impostor) = exposure * dumpSuccess + (1-exposure) * guess
 * </pre>
 * exposure≈1 时答对几乎不改变后验（信息量≈0），系统会自动把这类题排在后面。
 */
public final class LikelihoodScorer {

    /** 攻击者从泄露库取到答案后的正确率（数据可能过期，故不是 1）。 */
    static final double DUMP_SUCCESS = 0.93;
    /** 真用户“答错/记不清”的总概率上限，防止单题误伤。 */
    static final double MAX_SLIP = 0.35;
    /** 命中投毒事实时的对数几率加成。 */
    static final double CANARY_LOG_ODDS = 6.0;
    /** 投毒题里老老实实选“以上都没有”只算平反，不额外给正向证据。 */
    static final double CANARY_CLEAR_LOG_ODDS = 0.0;
    /** 单题证据封顶，避免任何一题（尤其用户手滑）一票否决。 */
    static final double PER_Q_CLAMP = 2.0;

    private static final List<String> NONE_LABELS = List.of("以上都没有", "都没有", "none", "无");

    public record Outcome(double logOdds, boolean canaryHit, boolean canaryCleared, double infoBits) {
    }

    public Outcome score(Question q, Set<String> selected, Set<String> canaryIds) {
        // ---- 拒答：明确的中性行为，既不奖励也不惩罚。 ----
        // 真用户常说“这个我记不清”，把它当答错就是在惩罚诚实。
        if (selected.isEmpty() && !isCanaryQuestion(q)) {
            return new Outcome(0.0, false, false, 0.0);
        }

        // ---- 投毒题：单独逻辑。 ----
        if (isCanaryQuestion(q)) {
            boolean hit = selected.stream().anyMatch(canaryIds::contains);
            if (hit) return new Outcome(CANARY_LOG_ODDS, true, false, q.bitCost());
            boolean cleared = selected.stream().map(LikelihoodScorer::normalize).anyMatch(NONE_LABELS::contains);
            return new Outcome(cleared ? CANARY_CLEAR_LOG_ODDS : 0.0, false, cleared, q.bitCost());
        }

        boolean correct = isCorrect(q, selected);
        double eps = Math.min(Math.max(q.userSlipProb(), 0.0), MAX_SLIP);
        double exposure = Math.min(Math.max(q.exposureProb(), 0.0), 1.0);
        long space = Math.max(q.answerSpace(), 1);
        double guess = 1.0 / space;

        double pCorrectImp = exposure * DUMP_SUCCESS + (1.0 - exposure) * guess;
        double pCorrectGen = 1.0 - eps;

        double lr;
        if (correct) {
            lr = pCorrectGen / Math.max(pCorrectImp, 1e-9);
        } else {
            long wrongSpace = Math.max(space - 1, 1);
            double pWrongGen = eps / wrongSpace;
            double pWrongImp = (exposure * (1.0 - DUMP_SUCCESS)
                    + (1.0 - exposure) * (1.0 - guess)) / wrongSpace;
            lr = pWrongGen / Math.max(pWrongImp, 1e-9);
        }

        return new Outcome(clamp(Math.log(lr), -PER_Q_CLAMP, PER_Q_CLAMP), false, false, 0.0);
    }

    /** 自由文本题按归一化字符串比较；选择题按 id 集合比较。 */
    static boolean isCorrect(Question q, Set<String> selected) {
        if (q.isFreeText()) {
            String a = normalize(selected.stream().findFirst().orElse(""));
            String b = normalize(q.correctOptionIds().stream().findFirst().orElse(""));
            return !a.isEmpty() && a.equals(b);
        }
        return selected.equals(Set.copyOf(q.correctOptionIds()));
    }

    public static boolean isCanaryQuestion(Question q) {
        return "canary".equals(q.dimension());
    }

    static String normalize(String s) {
        if (s == null) return "";
        String t = Normalizer.normalize(s.trim(), Normalizer.Form.NFKC).toLowerCase();
        return t.replaceAll("[\\s\\p{Punct}，。、]", "");
    }

    /**
     * 该题的“区分度权重”：越是泄露库里没有的事实，答对越值钱。
     *
     * <p>注意分数泄露题（PII/订单）权重被压到很低但不为零——
     * 它们只用于“要不要额外怀疑”，不能靠它们凑够放行的绝对权重。
     */
    public static double weight(Question q) {
        double raw = 1.0 - q.exposureProb();
        return switch (q.factClass()) {
            case CANARY -> 0.0;
            case PII_DUMPED, ORDER_DUMPED -> Math.min(0.25, raw);
            default -> clamp(raw, 0.05, 1.0);
        };
    }

    /**
     * 单次核验的通过判定。
     *
     * <p>设计目标：<b>把“诚实承认不确定”与“在猜”区分开</b>。
     *
     * <p>规则（而不是简单的加权平均）：
     * <ol>
     *   <li><b>泄露类题（PII/订单）不参与判定</b>：它们在泄露库里本来就有，
     *       答对不说明问题，答错也不该冤枉人（真用户也可能记错自己填过的地址）。
     *       它们只用于风险侧写，不用于放行。</li>
     *   <li><b>高区分度题必须“答对或拒答”</b>：真用户没把握时点“记不清”即可，
     *       拒答不扣分；但只要答了且答错，就算一次失误。</li>
     *   <li>至少答对 {@link #MIN_CORRECT_WEIGHT} 的高权重题、且失误不超过
     *       {@link #MAX_WRONG} 次、拒答不超过 {@link #MAX_DECLINE} 题。</li>
     * </ol>
     *
     * <p>为什么这样能挡住多次来电：攻击者不知道哪题该拒答（拒答对它没有信息增益），
     * 只能全答 → 每道高区分度题都是 1/选项数 的猜中率，多题连乘迅速趋零；
     * 而真用户靠“不确定就跳过”把通过率维持在高位。
     */
    public record Credit(double correctWeight, int answeredHigh, int wrongHigh,
                         int declinedHigh, int answeredLeak) {
        public boolean passes() {
            return correctWeight >= minCorrectWeight()
                    && wrongHigh <= maxWrong()
                    && declinedHigh <= maxDecline();
        }
    }

    /**
     * 这些阈值对外暴露成方法而非 static final 常量，
     * 因为扫描器需要在同一 JVM 内反复调参；常量一旦类初始化就固化了，
     * 会让“参数扫描”变成测同一个配置四遍的假实验。
     */
    /**
     * 放行所需的“高区分度题正确权重”。
     *
     * <p>取值来自参数扫描而非拍脑袋：0.9~1.7 是松弛区（5 题卷远高于门槛，
     * 调它几乎不影响结果）；越过 2.6 后攻击者通过率只从 0.7% 降到 0.4%，
     * 但记性差的真用户通过率会从 98.6% 掉到 92.4%。
     * 用 6 个百分点的用户损失换 0.3 个百分点的安全收益不划算，
     * 因此取 1.1——真正的主导防线是题数与诱饵数，不是这个门槛。
     */
    public static double minCorrectWeight() { return tunable("ivr.minCorrectWeight", 1.1); }
    public static int maxWrong() { return (int) tunable("ivr.maxWrong", 1); }
    public static int maxDecline() { return (int) tunable("ivr.maxDecline", 2); }
    /** 权重 ≥ 该值视为“高区分度题”，必须答对或拒答。 */
    public static final double HIGH_WEIGHT = 0.5;

    @Deprecated public static final double MIN_CORRECT_WEIGHT = 1.10;
    @Deprecated public static final int MAX_WRONG = 1;
    @Deprecated public static final int MAX_DECLINE = 2;

    /** 让规则可被外部扫描器调参——出题与计分规则是推敲出来的，不是拍出来的。 */
    private static double tunable(String key, double dflt) {
        String v = System.getProperty(key);
        if (v == null || v.isBlank()) return dflt;
        try { return Double.parseDouble(v); } catch (NumberFormatException e) { return dflt; }
    }

    public static Credit creditOf(List<Question> questions, Map<String, Set<String>> answers,
                                  Set<String> canaryHitFacts) {
        double correctW = 0;
        int answeredHigh = 0, wrongHigh = 0, declinedHigh = 0, answeredLeak = 0;
        for (Question q : questions) {
            if (isCanaryQuestion(q)) continue;          // 投毒题只做否决
            Set<String> sel = answers.getOrDefault(q.factId(), Set.of());
            boolean high = weight(q) >= HIGH_WEIGHT;
            if (!high) {                                 // 泄露类：只记录，不判定
                if (!sel.isEmpty()) answeredLeak++;
                continue;
            }
            if (sel.isEmpty()) { declinedHigh++; continue; }  // 拒答：不计错
            answeredHigh++;
            boolean ok = !canaryHitFacts.contains(q.factId()) && isCorrect(q, sel);
            if (ok) correctW += weight(q);
            else wrongHigh++;
        }
        return new Credit(correctW, answeredHigh, wrongHigh, declinedHigh, answeredLeak);
    }

    /** 该题对攻击者而言、即便答对也不改变后验的程度 → “问这题值不值”。 */
    public static double expectedInfoBits(Question q) {
        double exposure = Math.min(Math.max(q.exposureProb(), 0.0), 1.0);
        return log2(Math.max(q.answerSpace(), 1)) * (1.0 - exposure);
    }

    /** 该题一旦被问出，向外界泄露的“题目结构”信息量（用于暴露预算）。 */
    public static double askCostBits(Question q) {
        return Math.max(0.4, expectedInfoBits(q));
    }

    /** 由 Fact 生成题目时的缺省“有效信息位”，供编排器排序。 */
    public static double factValue(double exposureProb, long answerSpace) {
        double base = log2(Math.max(answerSpace, 1));
        return base * (1.0 - Math.min(Math.max(exposureProb, 0), 1));
    }

    private static double log2(double x) {
        return Math.log(x) / Math.log(2);
    }

    private static double clamp(double v, double lo, double hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private LikelihoodScorer() {
    }

    public static LikelihoodScorer create() {
        return new LikelihoodScorer();
    }

    public static List<String> describe() {
        return List.of(
                "P(correct|impostor) = exposure*dumpSuccess + (1-exposure)*guess",
                "LR = P(answer|genuine) / P(answer|impostor)",
                "per-question clamp ±2 log-odds; canary select +6, canary clear +0.8");
    }
}
