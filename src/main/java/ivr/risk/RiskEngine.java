package ivr.risk;

import ivr.model.AccountState;
import ivr.model.Quiz;

import java.util.List;

/**
 * 跨来电综合判断。单次来电的证据可能很弱，甚至故意“答对一半”来降风险；
 * 因此我们同时看：
 *  <ul>
 *   <li>账户上的累计风险（对数几率），只增不减，除非完成一次强核验；</li>
 *   <li>试探形态：短时多来电、同一来电号码打多个账户、同一账户多次换号、</li>
 *       只答 PII 不答行为题（防御性作答）；</li>
 *   <li>暴露预算：问出去的信息累计超过上限，就停止出题。</li>
 *  </ul>
 */
public final class RiskEngine {

    /** 每次来电本身的基础风险成本（陌生人打电话问账户信息）。 */
    public static final double PER_CALL_PRIOR = 0.35;

    /**
     * 单账户累计暴露信息位上限。
     *
     * <p>这道闸门与 {@code MAX_QUIZZES_PER_EPOCH} 是<b>重叠的两道防线</b>，
     * 分工必须分清，否则会互相踩踏：
     * <ul>
     *   <li>配额闸门按“次数”限制同一 epoch 内的抽奖机会；</li>
     *   <li>暴露预算按“信息量”限制<b>跨 epoch、跨天</b>的累积提取——
     *       攻击者可以等 24h 配额重置再来，但账户被问出去的事实总量是累计的。</li>
     * </ul>
     * 因此预算必须大于“一个 epoch 允许问出的量”，否则它会在第一次就抢先耗光，
     * 把真用户的正常重试也一起掐死（这是一个真实踩过的坑）。
     * 一次完整问卷约 6–9 bit，每 epoch 至多 3 份 → 预留约 3 份的余量。
     */
    public static final double EXPOSURE_BUDGET_BITS = 30.0;

    /** 触发高压处置的累计对数几率阈值。 */
    public static final double ESCALATE_THRESHOLD = 3.0;
    public static final double DENY_THRESHOLD = 6.5;

    /** 短时来电窗口：10 分钟内 3 次以上视为试探。 */
    public static final long PROBE_WINDOW_MILLIS = 10 * 60 * 1000L;
    public static final int PROBE_CALL_COUNT = 3;

    public record Verdict(
            Action action,
            double riskLogOdds,
            String internalReason,      // 只进日志，绝不给坐席/来电者
            double bitsRemaining,
            boolean cooldownStarted
    ) {
    }

    public enum Action {
        /** 正常办理（仍需 OOB 确认不可逆操作）。 */
        PROCEED,
        /** 追加线下/回调核验（对来电者的说法与 PROCEED 完全一致）。 */
        STEP_UP_OOB,
        /** 拒绝本次操作，转人工复核。 */
        DENY,
        /** 只登记、不办理，留作画像。 */
        MONITOR
    }

    private final ExposureLedger ledger = new ExposureLedger();

    /** 来电前的基线风险：账户历史 + 本次试探形态。 */
    public double preCallRisk(AccountState st, String aniTail, long now) {
        double r = st.riskLogOdds() + PER_CALL_PRIOR;

        long recent = st.calls().stream()
                .filter(c -> now - c.atMillis() <= PROBE_WINDOW_MILLIS)
                .count();
        if (recent >= PROBE_CALL_COUNT) {
            r += 1.2 + 0.35 * (recent - PROBE_CALL_COUNT); // 短时密集来电，递增
        }

        // 同一账户近期从多个不同号码进来 = 典型的换号试探。
        long distinctAni = st.calls().stream()
                .filter(c -> now - c.atMillis() <= 24 * 3600_000L)
                .map(AccountState.CallRecord::aniTail)
                .distinct()
                .count();
        if (distinctAni >= 2) r += 0.8 * (distinctAni - 1);

        return r;
    }

    /**
     * 记录一次来电并更新账户状态，返回是否因暴露预算耗尽而应停止出题。
     *
     * <p>注意：这里<b>只做提交</b>，不再重复累加 {@code bits}。
     * 调用方传入的 {@code bits} 仅用于通话记录展示；
     * 真正的扣减由 {@link ExposureLedger#commit} 统一完成。
     * （曾经两处都累加，导致预算被双倍消耗、真用户第一次就被封——真实踩过的坑。）
     */
    public boolean recordExposure(AccountState st, Quiz quiz, double bits, long now, String aniTail,
                                  String outcome) {
        ledger.commit(st, quiz);
        st.calls().add(new AccountState.CallRecord(now, aniTail, quiz.quizId(), bits, 0, outcome));
        return st.totalExposedBits() >= EXPOSURE_BUDGET_BITS;
    }

    /**
     * 单次来电对“冒充风险”的贡献上限（对数几率）。
     *
     * <p>为什么必须封顶：一次里答错多题会产生很大的负对数几率，
     * 若不封顶，一通搞砸的电话就直接把风险推到 DENY，把真用户（尤其是
     * 第一次用语音、没听清格式的人）一棍子打死。封顶后：
     * <ul>
     *   <li>一次失败 → 升级为“需线下核验”，仍可再来；</li>
     *   <li>两次失败 → 接近拒绝；</li>
     *   <li>命中投毒 → 另有 +3 的直接惩罚，可立即拒绝。</li>
     * </ul>
     */
    public static final double MAX_RISK_DELTA_PER_CALL = 3.2;

    /**
     * 作答后的风险更新。
     *
     * <p>符号约定：{@code quizLogOdds > 0} 表示证据更支持“真用户”，
     * 因此应当<b>降低</b>冒充风险；负数才是可疑证据。绝不把“答对”加成风险。
     *
     * @param behavioralAsymmetry 泄露题答得好、行为题却答得差 → 强信号
     */
    public void applyScoreEvidence(AccountState st, double quizLogOdds, double behavioralAsymmetry) {
        // 一次来电带来的风险变化封顶，避免单次失误导致永久封禁。
        double delta = Math.max(-MAX_RISK_DELTA_PER_CALL,
                Math.min(MAX_RISK_DELTA_PER_CALL, -quizLogOdds));
        st.addRisk(delta);
        if (behavioralAsymmetry > 1.0) {
            // 防御性作答：像一个只背了泄露库的人。
            st.addRisk(Math.min(2.0, behavioralAsymmetry));
        }
        // 风险不会为负：核验通过可清零，但清零不等于“洗白历史试探形态”——
        // 试探形态另由 preCallRisk 每次重新计入。
        st.setRisk(Math.max(st.riskLogOdds(), 0));
    }

    public Verdict decide(AccountState st, double preRisk, boolean quizPassed, double bitsRemaining) {
        double total = st.riskLogOdds();

        if (total >= DENY_THRESHOLD) {
            return new Verdict(Action.DENY, total, "risk>=deny", bitsRemaining, false);
        }
        if (bitsRemaining <= 0) {
            // 预算耗尽：不再出题，只能线下。对来电者表现为“需要补充核验”。
            return new Verdict(Action.STEP_UP_OOB, total, "exposure budget exhausted",
                    bitsRemaining, false);
        }
        if (total >= ESCALATE_THRESHOLD) {
            return new Verdict(Action.STEP_UP_OOB, total, "risk>=escalate", bitsRemaining, false);
        }
        if (!quizPassed && preRisk >= PER_CALL_PRIOR) {
            return new Verdict(Action.STEP_UP_OOB, total, "quiz not passed", bitsRemaining, false);
        }
        return new Verdict(Action.PROCEED, total, "ok", bitsRemaining, false);
    }

    public double bitsRemaining(AccountState st) {
        return Math.max(0, EXPOSURE_BUDGET_BITS - st.totalExposedBits());
    }
}
