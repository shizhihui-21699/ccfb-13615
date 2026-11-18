package ivr.model;

/**
 * 事实的“泄露类别”。这个分类是整套系统的核心：
 * 它决定一个事实能不能被当成核验问题，以及它的信息量上限。
 *
 * 背景：攻击者手里往往有电商/运营商的泄露库。凡是能从库里查到的事实，
 * 无论多“隐私”，对攻击者都是免费答案，出题就是在送分。
 */
public enum FactClass {
    /** 姓名、生日、住址、身份证、邮箱、手机号：几乎必在泄露库里。 */
    PII_DUMPED,
    /** 订单号、订单金额、下单日期、收货城市：电商泄露库常见。 */
    ORDER_DUMPED,
    /** 行为侧写：最常转账对象的昵称、常用设备、近期偏好商户。库里有也不全。 */
    BEHAVIOR,
    /** 聚合统计：近半年充值次数区间等。库里通常没有，但用户记忆也偏模糊。 */
    DERIVED,
    /** 开户/上次核验时与本人约定的暗语。与泄露数据完全无关。 */
    CO_SET_SECRET,
    /** 投毒事实：只存在于我们故意放出去的“假泄露库”里。 */
    CANARY;

    /** 该类别的事实在真实泄露库中的典型命中率，仅作为出题时的先验。 */
    public double typicalDumpHitRate() {
        return switch (this) {
            case PII_DUMPED -> 0.95;
            case ORDER_DUMPED -> 0.80;
            case BEHAVIOR -> 0.20;
            case DERIVED -> 0.05;
            case CO_SET_SECRET -> 0.00;
            case CANARY -> 0.00; // 合法库中为 0，投毒库中为 1
        };
    }
}
