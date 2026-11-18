package ivr.qa;

import ivr.model.Fact;
import ivr.model.FactClass;
import ivr.model.Option;
import ivr.model.Question;
import ivr.model.Quiz;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * 出题编排器。目标：在“不刁难真用户”的约束下，最大化
 * 本次核验对“持有泄露库的攻击者”的区分度。
 *
 * <p>约束与策略：
 * <ul>
 *   <li>题量小（默认 3），只问一次、盲答、整批提交，杜绝逐题试探。</li>
 *   <li>按有效信息位降序挑题——泄露程度高的题信息位≈0，自然沉底被裁掉。</li>
 *   <li>至少一道“非泄露类”题（行为/统计/暗语），否则整卷无区分度。</li>
 *   <li>真用户记忆噪声预算：整卷 userSlip 预期之和不超过题数的一半，
 *       保证“多数题真有把握”，而不是把人逼到只能瞎蒙。</li>
 *   <li>投毒题是独立附加题，绝不污染普通题选项（否则真用户误中率≈1/5）。</li>
 * </ul>
 */
public final class QuizBuilder {

    public static int quizSize() { return (int) tunable("ivr.quizSize", 5); }

    private static double tunable(String key, double dflt) {
        String v = System.getProperty(key);
        if (v == null || v.isBlank()) return dflt;
        try { return Double.parseDouble(v); } catch (NumberFormatException e) { return dflt; }
    }

    private final FactExtractor extractor = new FactExtractor();
    private final OptionPool pool;

    public QuizBuilder(OptionPool pool) {
        this.pool = pool;
    }

    public record BuildResult(Quiz quiz, boolean budgetExhausted, double bitsThisQuiz) {
    }

    public BuildResult build(ivr.model.Account acct, int epoch, boolean allowCanary,
                             double maxBitsThisQuiz) {
        List<Fact> facts = extractor.extract(acct);

        record Cand(Fact f, double value, double cost, double slip) {}
        List<Cand> cands = new ArrayList<>();
        for (Fact f : facts) {
            long space = answerSpaceFor(f);
            double value = LikelihoodScorer.factValue(f.exposureProb(), space);
            cands.add(new Cand(f, value, Math.max(0.4, value), f.userSlipProb()));
        }
        cands.sort(Comparator.comparingDouble(Cand::value).reversed()
                .thenComparing(c -> c.f().id()));

        List<Cand> chosen = new ArrayList<>();
        double slipSum = 0, bits = 0;
        boolean hasNonLeak = false;

        for (Cand c : cands) {
            if (chosen.size() >= quizSize()) break;
            if (bits + c.cost() > maxBitsThisQuiz) continue;          // 暴露预算
            if (slipSum + c.slip() > quizSize() * 0.55) continue; // 别逼死真用户
            boolean nonLeak = c.f().factClass() != FactClass.PII_DUMPED
                    && c.f().factClass() != FactClass.ORDER_DUMPED;
            if (!nonLeak && !hasNonLeak) continue;                    // 先给非泄露题留位
            chosen.add(c);
            slipSum += c.slip();
            bits += c.cost();
            hasNonLeak |= nonLeak;
        }
        if (chosen.isEmpty()) {
            for (Cand c : cands) {
                if (c.cost() <= maxBitsThisQuiz) { chosen.add(c); bits += c.cost(); break; }
            }
        }
        if (chosen.isEmpty()) return new BuildResult(null, true, 0);

        List<Question> questions = new ArrayList<>();
        // 该用户所有事实的答案 + 用过的商户，全部禁止作为诱饵。
        // 这样任何一道题的错选项都不会恰好是另一道题的正确答案。
        Set<String> forbidden = forbiddenLabels(acct, chosen.stream().map(Cand::f).toList());
        for (Cand c : chosen) questions.add(toQuestion(acct.accountId(), epoch, c.f(), forbidden));

        // 投毒题：独立附加，不计入泄露题预算之外的额外信息位。
        if (allowCanary) {
            questions.add(canaryQuestion(acct.accountId(), epoch, acct.merchantsUsed()));
        }

        String quizId = "q-" + UUID.randomUUID();
        return new BuildResult(new Quiz(quizId, acct.accountId(), System.currentTimeMillis(),
                List.copyOf(questions), allowCanary), false, bits);
    }

    /**
     * 计算“不得作为诱饵”的标签集合。
     *
     * <p>包含三类：
     * <ol>
     *   <li>本卷所有事实的正确答案；</li>
     *   <li>该用户全部事实的答案（即使本轮没问到——今天的没问到，不代表明天不会问）；</li>
     *   <li>该用户用过的商户名（商户池与诱饵池同源，最容易互相污染）。</li>
     * </ol>
     */
    private Set<String> forbiddenLabels(ivr.model.Account acct, List<Fact> inQuiz) {
        Set<String> forbidden = new HashSet<>();
        if (acct.merchantsUsed() != null) forbidden.addAll(acct.merchantsUsed());
        for (Fact f : extractor.extract(acct)) {
            if (f.value() != null) forbidden.add(String.valueOf(f.value()));
        }
        for (Fact f : inQuiz) {
            if (f.value() != null) forbidden.add(String.valueOf(f.value()));
        }
        return forbidden;
    }

    private Question toQuestion(String accountId, int epoch, Fact f, Set<String> forbidden) {
        String dim = f.dimension();
        String seedKey = accountId + "|" + dim + "|" + epoch;

        if (dim.equals("secret")) {
            // 暗语题无选项：攻击者无法靠排除法收敛，答案空间是人名/短语级。
            // 注意暴露成本：问这道题并不会把“答案”泄露出去（对方本来就要猜），
            // 真正的成本上限是“确认有人在用暗语核验”这一点点信息，故给固定小额，
            // 不能用 log2(answerSpace) 来算——否则自由文本题会一次吃掉全部预算。
            return new Question(f.id(), dim, f.factClass(), f.prompt(), List.of(),
                    List.of(String.valueOf(f.value())), 2000,
                    f.exposureProb(), f.userSlipProb(), f.sensitivity(), 0.8);
        }

        String poolName = poolNameFor(f);
        String correctLabel = String.valueOf(f.value());
        int kDecoys = (int) Math.round(tunable("ivr.decoys", 4.0));
        List<Option> options = pool.buildStableOptions(seedKey, List.of(correctLabel),
                poolName, kDecoys, false, forbidden);

        List<String> correctIds = new ArrayList<>();
        for (Option o : options) if (o.label().equals(correctLabel)) correctIds.add(o.id());

        return new Question(f.id(), dim, f.factClass(), f.prompt(), List.copyOf(options),
                List.copyOf(correctIds), options.size(), f.exposureProb(),
                f.userSlipProb(), f.sensitivity(),
                // 暴露成本 = 选项空间的规模（问出来就等于把选项池亮给了对方），
                // 而不是“答案的信息量”。两者被混淆过一次，会让预算瞬间清零。
                Math.max(0.4, Math.log(options.size()) / Math.log(2)));
    }

    /**
     * 投毒题：给出 2 个用户从未用过的“投毒商户” + 若干真实用过的商户 + “以上都没有”。
     * 真用户选自己的真实商户（或“以上都没有”也是安全的）；照库念的攻击者会选中投毒项。
     */
    private Question canaryQuestion(String accountId, int epoch, Set<String> usedMerchants) {
        String seedKey = accountId + "|canary|" + epoch;
        List<String> used = new ArrayList<>(usedMerchants);
        List<String> correct = used.isEmpty() ? List.of() : used.subList(0, Math.min(2, used.size()));

        List<Option> opts = pool.buildCanaryQuestion(seedKey, List.copyOf(correct), true);
        List<String> correctIds = new ArrayList<>();
        for (Option o : opts) if (correct.contains(o.label())) correctIds.add(o.id());

        // 这道题的 exposure 不用于常规似然比（走投毒专用逻辑），给 0。
        return new Question("canary", "canary", FactClass.CANARY,
                "以下商户中，哪些是您在本平台实际消费过的？不确定的就不用选。",
                opts, List.copyOf(correctIds), opts.size(),
                0.0, 0.0, 0.3, 1.5);
    }

    private String poolNameFor(Fact f) {
        return switch (f.id()) {
            case "counterparty" -> "nickname";
            case "device" -> "device";
            case "addressCity", "lastOrderCity" -> "city";
            case "topupsBucket" -> "bucket";
            default -> "merchant";
        };
    }

    private long answerSpaceFor(Fact f) {
        return switch (f.factClass()) {
            case CO_SET_SECRET -> 2000;
            case DERIVED -> 5;
            case BEHAVIOR -> 6;
            default -> 5;
        };
    }

    public Set<String> canaryOptionIds(Question q) {
        Set<String> ids = new HashSet<>();
        Set<String> canaryLabels = pool.canaryLabels();
        for (Option o : q.options()) if (canaryLabels.contains(o.label())) ids.add(o.id());
        return ids;
    }

    public Map<String, String> labelIndex(Question q) {
        Map<String, String> m = new HashMap<>();
        for (Option o : q.options()) m.put(o.id(), o.label());
        return m;
    }
}
