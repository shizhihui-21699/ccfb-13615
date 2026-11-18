package ivr.model;

/**
 * 账户的跨来电核验状态。这是唯一能对抗“换号码反复来电”的东西：
 * 计数器挂在账户上，不挂来电号码上。
 */
public final class AccountState {

    /** 已经向外界“展示过”的事实 -> 已消耗的信息位数。用于暴露预算。 */
    private final java.util.Map<String, Double> exposedBits = new java.util.LinkedHashMap<>();

    /** 当前 epoch 内该维度是否已经泄露（一旦泄露，同维度后续题目近乎无效）。 */
    private final java.util.Map<String, Boolean> dimensionBurned = new java.util.HashMap<>();

    /** 累计风险打分（对数几率）。越高越可疑。 */
    private double riskLogOdds = 0.0;

    /** 历史来电记录（用于渐进式试探识别）。 */
    private final java.util.List<CallRecord> calls = new java.util.ArrayList<>();

    /** 已触发过几次“高风险”处置。 */
    private int escalationCount = 0;

    /** 冷却截止时间（触发改绑冷却后，期间不得再次改绑）。 */
    private long cooldownUntilMillis = 0;

    /** 当前 epoch。泄露预算用尽后递增，换一批题面选项（但不会因此给攻击者更多信号）。 */
    private int epoch = 0;

    public record CallRecord(long atMillis, String aniTail, String quizId,
                             double bitsExposed, double riskDelta, String outcome) {
    }

    /** 当前 epoch 已发出的问卷数，用于限制“换号多次来抽奖”。 */
    private int quizzesThisEpoch = 0;

    /** 已通过但尚在冷却中的操作，防止通过后立即改绑。 */
    private long lastPassAtMillis = 0;

    /** 上次配额重置时间（用于 24h 自动恢复）。 */
    private long lastQuotaResetMillis = 0;

    public int quizzesThisEpoch() { return quizzesThisEpoch; }
    public void incQuizzesThisEpoch() { quizzesThisEpoch++; }
    public void resetQuizzesThisEpoch() { quizzesThisEpoch = 0; }
    public long lastPassAtMillis() { return lastPassAtMillis; }
    public void setLastPassAtMillis(long t) { lastPassAtMillis = t; }
    public long lastQuotaResetMillis() { return lastQuotaResetMillis; }
    public void setLastQuotaResetMillis(long t) { lastQuotaResetMillis = t; }

    public java.util.Map<String, Double> exposedBits() { return exposedBits; }
    public java.util.Map<String, Boolean> dimensionBurned() { return dimensionBurned; }
    public double riskLogOdds() { return riskLogOdds; }
    public void addRisk(double d) { riskLogOdds += d; }
    public void setRisk(double v) { riskLogOdds = v; }
    public java.util.List<CallRecord> calls() { return calls; }
    public int escalationCount() { return escalationCount; }
    public void incEscalation() { escalationCount++; }
    public long cooldownUntilMillis() { return cooldownUntilMillis; }
    public void setCooldownUntilMillis(long t) { cooldownUntilMillis = t; }
    public int epoch() { return epoch; }
    public void bumpEpoch() { epoch++; }

    public double totalExposedBits() {
        return exposedBits.values().stream().mapToDouble(Double::doubleValue).sum();
    }
}
