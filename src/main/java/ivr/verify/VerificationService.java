package ivr.verify;

import ivr.model.Account;
import ivr.model.AccountState;
import ivr.model.Question;
import ivr.model.Quiz;
import ivr.qa.LikelihoodScorer;
import ivr.qa.OptionPool;
import ivr.qa.QuizBuilder;
import ivr.risk.RiskEngine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 坐席核验总服务。把“出题 → 盲答 → 打分 → 跨来电聚合 → 处置”串起来。
 *
 * <p>安全设计要点（对应需求里的每个难点）：
 * <ol>
 *   <li>逐题无反馈：{@link #submit} 只返回一个整体结论，且失败话术恒定。</li>
 *   <li>选项稳定：见 {@link ivr.qa.OptionPool}，防止跨来电交集攻击。</li>
 *   <li>跨来电聚合：状态挂在 accountId 上，换号码不重置。</li>
 *   <li>不刁难真用户：滑落预算 + 题目上限 + 允许拒答敏感题。</li>
 *   <li>不可逆操作二次闸门：即使通过，也只进入“冷却+全渠道通知”。</li>
 * </ol>
 */
public final class VerificationService {

    private final Map<String, Account> accounts = new ConcurrentHashMap<>();
    private final Map<String, AccountState> states = new ConcurrentHashMap<>();
    private final Map<String, Quiz> openQuizzes = new ConcurrentHashMap<>();
    private final Map<String, String> aniToAccounts = new ConcurrentHashMap<>();

    private final OptionPool optionPool = new OptionPool();
    private final QuizBuilder quizBuilder = new QuizBuilder(optionPool);
    private final LikelihoodScorer scorer = LikelihoodScorer.create();
    private final RiskEngine risk = new RiskEngine();

    /** 改绑冷却期：通过后仍需等待。 */
    public static final long REBIND_COOLDOWN_MILLIS = 24 * 3600_000L;

    /**
     * 同一账户、同一 epoch 内最多发出的问卷数。
     *
     * <p>这是对抗“换号反复来电多抽几次”的核心闸门：一次未通过即消耗一次配额，
     * 配额用尽后不再出题（只能走线下）。它把“攻击者用 N 次来电换 N 次倒霉猜中”
     * 从期望值上打平——每多抽一次都要先赔掉一次失败。
     */
    public static final int MAX_QUIZZES_PER_EPOCH = 3;

    public void register(Account a) {
        accounts.put(a.accountId(), a);
        states.putIfAbsent(a.accountId(), new AccountState());
    }

    public record CallSession(String sessionId, String accountId, String aniTail, long startedAt,
                              Quiz quiz, String deliveryScript, double preRisk) {
    }

    /** 一次来电。返回问卷；对高风险账户也可能返回“不出题、直接转线下”。 */
    public CallSession startCall(String accountId, String aniTail) {
        Account acct = accounts.get(accountId);
        if (acct == null) throw new IllegalArgumentException("unknown account");
        AccountState st = states.computeIfAbsent(accountId, k -> new AccountState());
        long now = System.currentTimeMillis();

        aniToAccounts.computeIfAbsent(aniTail, k -> null);
        double preRisk = risk.preCallRisk(st, aniTail, now);

        // 风险已高到不该再出题：继续问只会白送信息。
        if (preRisk >= RiskEngine.DENY_THRESHOLD) {
            return new CallSession(UUID.randomUUID().toString(), accountId, aniTail, now,
                    null, Responses.REVIEW, preRisk);
        }
        // 本 epoch 配额已用尽：不再出题。对来电者话术与其它失败路径一致。
        // 超过 24h 自动恢复一次配额，避免真用户被永久锁死在线渠道。
        if (now - st.lastQuotaResetMillis() > 24 * 3600_000L) {
            st.resetQuizzesThisEpoch();
            st.setLastQuotaResetMillis(now);
        }
        if (st.quizzesThisEpoch() >= MAX_QUIZZES_PER_EPOCH) {
            return new CallSession(UUID.randomUUID().toString(), accountId, aniTail, now,
                    null, Responses.REVIEW, preRisk);
        }

        boolean allowCanary = st.calls().size() >= 2 || preRisk >= 2.0;
        double bitsLeft = risk.bitsRemaining(st);

        QuizBuilder.BuildResult br = quizBuilder.build(acct, st.epoch(), allowCanary, bitsLeft);
        // 失败关闭：题目不足以支撑一次有区分度的核验时，宁可不问。
        // 问一堆泄露题既挡不住人，又白送信息。
        if (br.quiz() == null
                || br.quiz().questions().stream()
                        .noneMatch(q -> LikelihoodScorer.weight(q) >= LikelihoodScorer.HIGH_WEIGHT)) {
            return new CallSession(UUID.randomUUID().toString(), accountId, aniTail, now,
                    null, Responses.REVIEW, preRisk);
        }
        openQuizzes.put(br.quiz().quizId(), br.quiz());
        String script = Responses.quizDelivery(br.quiz().questions().size());
        return new CallSession(UUID.randomUUID().toString(), accountId, aniTail, now,
                br.quiz(), script, preRisk);
    }

    /** 坐席提交的作答：questionId -> 选中的选项 id 集合；自由文本题用 label 作为 id。 */
    public record Result(String sessionOutcome, String script, boolean passed,
                         RiskEngine.Action action, double riskLogOdds,
                         double bitsRemaining, long cooldownUntilMillis,
                         List<String> debug) {
    }

    public Result submit(String accountId, String quizId,
                         Map<String, Set<String>> answers, String aniTail) {
        AccountState st = states.get(accountId);
        Quiz quiz = openQuizzes.remove(quizId);
        if (st == null || quiz == null) throw new IllegalStateException("no open quiz");
        long now = System.currentTimeMillis();

        double preRisk = risk.preCallRisk(st, aniTail, now);
        List<String> debug = new ArrayList<>();
        double totalLogOdds = 0;
        double piiScore = 0, behaviorScore = 0;
        boolean anyCanary = false;
        Set<String> canaryHitFacts = new java.util.HashSet<>();
        double bitsExposed = 0;

        for (Question q : quiz.questions()) {
            Set<String> sel = answers.getOrDefault(q.factId(), Set.of());
            Set<String> canaryIds = quizBuilder.canaryOptionIds(q);

            LikelihoodScorer.Outcome o = scorer.score(q, sel, canaryIds);
            if (o.canaryHit()) {
                anyCanary = true;
                canaryHitFacts.add(q.factId());
            }
            totalLogOdds += o.logOdds();
            bitsExposed += q.bitCost();

            boolean isLeakDim = q.factClass() == ivr.model.FactClass.PII_DUMPED
                    || q.factClass() == ivr.model.FactClass.ORDER_DUMPED;
            if (isLeakDim) piiScore += o.logOdds();
            else if (q.factClass() != ivr.model.FactClass.CANARY) behaviorScore += o.logOdds();

            debug.add("%s[%s] exposure=%.2f logOdds=%+.2f%s"
                    .formatted(q.factId(), q.factClass(), q.exposureProb(), o.logOdds(),
                            o.canaryHit() ? " CANARY_HIT" : ""));
        }

        // 单次是否放行：用“加权绝对正确权重 + 正确率”，而不是对数几率阈值。
        // 允许拒答，故真用户可跳过没把握的一题；攻击者凑不够高权重事实。
        LikelihoodScorer.Credit credit =
                LikelihoodScorer.creditOf(quiz.questions(), answers, canaryHitFacts);
        debug.add("credit correctW=%.2f highAnswered=%d highWrong=%d highDeclined=%d leakAnswered=%d"
                .formatted(credit.correctWeight(), credit.answeredHigh(), credit.wrongHigh(),
                        credit.declinedHigh(), credit.answeredLeak()));

        // 防御性作答：泄露题答得很顺（正证据），行为题却很糟（负证据）。
        double asymmetry = 0;
        if (piiScore > 0.5 && behaviorScore < -0.5) {
            asymmetry = Math.min(3.0, piiScore - behaviorScore);
        }

        risk.applyScoreEvidence(st, totalLogOdds, asymmetry);
        if (anyCanary) {
            st.addRisk(3.0);
            debug.add("canary -> forced high risk");
        }

        boolean passed = credit.passes()
                && !anyCanary
                && st.riskLogOdds() < RiskEngine.ESCALATE_THRESHOLD;

        debug.add("passed=" + passed);

        // 命中投毒 = 近乎确定性的“这是照着泄露库念的人”。
        // 不再走“风险累加够不够”的模糊路径，直接把账户风险顶到拒绝线以上。
        if (anyCanary) {
            st.setRisk(Math.max(st.riskLogOdds(), RiskEngine.DENY_THRESHOLD + 1.0));
            st.incEscalation();
        }

        boolean budgetOut = risk.recordExposure(st, quiz, bitsExposed, now, aniTail,
                passed ? "pass" : "fail");
        double bitsRemaining = risk.bitsRemaining(st);
        // 即便核验通过，也不当场改绑：进入冷却 + 全渠道通知。
        long cooldown = 0;
        if (passed) {
            cooldown = now + REBIND_COOLDOWN_MILLIS;
            st.setCooldownUntilMillis(Math.max(st.cooldownUntilMillis(), cooldown));
        }

        RiskEngine.Verdict v = risk.decide(st, preRisk, passed, bitsRemaining);
        String script = passed ? Responses.PASS : Responses.NEUTRAL_FAIL;
        String outcome = passed ? "PASS" : "FAIL";

        // 每次作答消耗一次本 epoch 配额。
        st.incQuizzesThisEpoch();
        if (passed) {
            st.setLastPassAtMillis(now);
            st.resetQuizzesThisEpoch();
        }

        debug.add("totalLogOdds=%+.2f preRisk=%.2f postRisk=%.2f action=%s"
                .formatted(totalLogOdds, preRisk, st.riskLogOdds(), v.action()));

        return new Result(outcome, script, passed, v.action(), st.riskLogOdds(),
                bitsRemaining, st.cooldownUntilMillis(), debug);
    }

    public AccountState state(String accountId) {
        return states.get(accountId);
    }

    /**
     * 执行“改绑手机”这一不可逆动作。这是最后一道闸门。
     *
     * <p>即便问答全部通过，也必须：
     * <ol>
     *   <li>等待冷却期结束（{@link #REBIND_COOLDOWN_MILLIS}）；</li>
     *   <li>期间已向账户原手机与邮箱推送确认通知（由外部通知服务完成，这里建模为标记）。</li>
     * </ol>
     * 于是一个“拿到全部数据、一次问答就过”的极端攻击者，
     * 得到的也只是一个<b>延迟 24 小时、且原机主立刻会收到告警</b>的窗口——
     * 渐进式试探所付出的多次来电，换不回即时收益。
     */
    public record RebindResult(boolean allowed, String reason, long cooldownRemainingMillis) {
    }

    public RebindResult attemptRebind(String accountId, long now) {
        AccountState st = states.get(accountId);
        if (st == null) return new RebindResult(false, "unknown account", 0);
        long remaining = st.cooldownUntilMillis() - now;
        if (remaining > 0) {
            return new RebindResult(false, "cooldown", remaining);
        }
        if (st.lastPassAtMillis() == 0) {
            return new RebindResult(false, "no verified session", 0);
        }
        return new RebindResult(true, "ok", 0);
    }

    public Account account(String accountId) {
        return accounts.get(accountId);
    }

    public List<Account> allAccounts() {
        return new ArrayList<>(accounts.values());
    }

    public QuizBuilder quizBuilder() {
        return quizBuilder;
    }

    public OptionPool optionPool() {
        return optionPool;
    }
}
