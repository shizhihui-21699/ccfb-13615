package ivr.model;

import java.util.List;

/**
 * 一个账户的可核验事实。value 的语义由 questionKind 决定：
 *  - SINGLE_CHOICE / MULTI_CHOICE：正确地形的“选项 id”集合
 *  - ENUM_INTERVAL：用户所属的区间标签
 *  - NONE_OF_THESE 类（trap）：正确作答就是“以上都不对”
 */
public record Fact(
        String id,
        FactClass factClass,
        String dimension,      // 同一维度的多个问题共享选项空间与“已泄露”状态
        String prompt,         // 坐席话术
        Object value,
        /** 该事实被单独泄露/可被搜索引擎或社工推出的概率估计。 */
        double exposureProb,
        /** 用户本人在电话里答错/记不清的边缘概率（记忆噪声）。 */
        double userSlipProb,
        /** 该事实是否适合作为“可拒答”的安全题（敏感度越高越应允许拒答）。 */
        double sensitivity) {
}
