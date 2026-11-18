package ivr.model;

import java.util.List;

/**
 * 一道实际的题目实例。关键设计：
 *  - 选项集合对同一 账户+维度+epoch 是确定的（不随来电漂移），
 *    否则攻击者可以用“两次来电的选项集合做交集”反推答案。
 *  - correctOptionIds 只留在服务端。
 *  - answerSpace 显式给出“瞎猜命中”的概率分母：选择题=选项数，
 *    自由文本=可能的取值规模。没有它，自由文本题的似然比会算错。
 *  - 不暴露“这题有多少个正确答案”。
 */
public record Question(
        String factId,
        String dimension,
        FactClass factClass,
        String prompt,
        List<Option> options,
        List<String> correctOptionIds,
        int answerSpace,
        double exposureProb,     // 该题答案对攻击者的可获得性
        double userSlipProb,     // 真用户答错的概率
        double sensitivity,
        /** 该题要消耗的攻击者“信息位”，用于暴露预算。 */
        double bitCost) {

    public boolean isMulti() {
        return correctOptionIds.size() > 1;
    }

    public boolean isFreeText() {
        return options.isEmpty();
    }
}
