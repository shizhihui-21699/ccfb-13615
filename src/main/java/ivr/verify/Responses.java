package ivr.verify;

/**
 * 对来电者“说出口”的话术。
 *
 * <p>铁律：<b>无论内部判定如何，只要没通过，对外措辞逐字相同。</b>
 * 否则攻击者就能靠措辞差异（“答错了”vs“信息不匹配”vs“需要补充核验”）
 * 反推自己哪一题踩中了。这里用同一个字符串常量，从源头堵死。
 */
public final class Responses {

    /** 交付问卷：对所有账户、所有风险等级，包装方式都一样。 */
    public static String quizDelivery(int questionCount) {
        return "为了账户安全，我需要向您核对几项信息。请您一次性告诉我："
                + "下面 %d 道题各选哪一项，不用逐题确认，我最后统一核对。".formatted(questionCount);
    }

    /**
     * 核验未通过。注意：没有“错了”“不对”“差一点”“请再想想”这类词。
     * 也不透露是哪一题、错了几题。
     */
    public static final String NEUTRAL_FAIL =
            "感谢您的配合。您提供的信息与账户记录不能完全匹配，本次暂时无法在线办理。"

            + "如需继续处理，我们会通过您预留的联系方式与您联系，请您留意。";

    /** 通过。注意：通过话术也不能描述“你答对了哪几题”。 */
    public static final String PASS =
            "信息核对完成。由于本次涉及安全设置变更，我们会先向您预留的手机和邮箱发送确认，"
                    + "确认后 24 小时内生效。您现在还有其他需要协助的吗？";

    /** 触发风控的高压处置：对外与 NEUTRAL_FAIL 完全一致。 */
    public static final String REVIEW = NEUTRAL_FAIL;

    private Responses() {
    }
}
