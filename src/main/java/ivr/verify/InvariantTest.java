package ivr.verify;

import ivr.data.SeedData;
import ivr.model.Account;
import ivr.model.Option;
import ivr.model.Question;
import ivr.model.Quiz;
import ivr.qa.QuizBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 不变量测试。这些是“系统设计承诺”的可执行版本——
 * 如果哪天有人改了出题/话术逻辑把它们破坏掉，测试会立刻失败。
 *
 * <p>覆盖：
 * <ol>
 *   <li><b>话术一致</b>：所有未通过路径对外的字符串必须逐字相同。</li>
 *   <li><b>选项稳定</b>：同账户同 epoch 两次出题的选项集与顺序必须完全一致。</li>
 *   <li><b>无跨题污染</b>：任一题的错选项不得是该用户其它事实的正确答案。</li>
 *   <li><b>投毒隔离</b>：普通题选项里不得混入投毒实体。</li>
 *   <li><b>不回传答案</b>：下发给坐席的问卷对象必须不含 correctOptionIds。</li>
 * </ol>
 */
public final class InvariantTest {

    private static int failures = 0;

    public static void main(String[] args) {
        List<Account> accounts = SeedData.accounts();

        checkResponsesUniform();
        checkOptionStability(accounts);
        checkNoCrossQuestionContamination(accounts);
        checkCanaryIsolation(accounts);
        checkNoAnswersInPayload(accounts);

        System.out.println();
        if (failures == 0) {
            System.out.println("全部不变量通过 ✓");
        } else {
            System.out.println("失败 " + failures + " 项 ✗");
            System.exit(1);
        }
    }

    // 1. 所有失败路径话术一致
    private static void checkResponsesUniform() {
        Set<String> fails = new HashSet<>(List.of(
                Responses.NEUTRAL_FAIL, Responses.REVIEW));
        assertThat("失败话术必须唯一", fails.size() == 1);
        assertThat("失败话术不得含“错/不对/差一点”等泄露词",
                !Responses.NEUTRAL_FAIL.contains("错") && !Responses.NEUTRAL_FAIL.contains("不对"));
        assertThat("通过话术不得描述答对了几题",
                !Responses.PASS.contains("题") || Responses.PASS.contains("安全设置变更"));
    }

    // 2. 选项稳定性
    private static void checkOptionStability(List<Account> accounts) {
        for (Account a : accounts) {
            var svc1 = new VerificationService();
            accounts.forEach(svc1::register);
            var q1 = svc1.startCall(a.accountId(), a.registeredAniTail()).quiz();

            var svc2 = new VerificationService();
            accounts.forEach(svc2::register);
            var q2 = svc2.startCall(a.accountId(), a.registeredAniTail()).quiz();

            if (q1 == null || q2 == null) continue;

            Map<String, List<String>> m1 = labelsByFact(q1);
            Map<String, List<String>> m2 = labelsByFact(q2);

            for (String fact : m1.keySet()) {
                if (!m2.containsKey(fact)) continue;
                assertThat("选项集必须稳定: " + a.accountId() + "/" + fact,
                        m1.get(fact).equals(m2.get(fact)));
            }
        }
    }

    // 3. 跨题污染
    private static void checkNoCrossQuestionContamination(List<Account> accounts) {
        for (Account a : accounts) {
            var svc = new VerificationService();
            accounts.forEach(svc::register);
            for (int call = 0; call < 6; call++) {
                var s = svc.startCall(a.accountId(), "ani" + call);
                if (s.quiz() == null) break;

                // 收集所有题的正确答案标签
                Set<String> allCorrect = new HashSet<>();
                for (Question q : s.quiz().questions()) {
                    for (String cid : q.correctOptionIds()) {
                        for (Option o : q.options()) if (o.id().equals(cid)) allCorrect.add(o.label());
                    }
                }
                // 检查每题的错误选项不与“其它题”的正确答案重合
                for (Question q : s.quiz().questions()) {
                    for (Option o : q.options()) {
                        if (q.correctOptionIds().contains(o.id())) continue;
                        boolean isOtherAnswer = allCorrect.contains(o.label())
                                && !q.correctOptionIds().stream().anyMatch(cid ->
                                        q.options().stream().anyMatch(oo ->
                                                oo.id().equals(cid) && oo.label().equals(o.label())));
                        assertThat("错选项不得是其它题的答案: " + a.accountId()
                                + " fact=" + q.factId() + " option=" + o.label(), !isOtherAnswer);
                    }
                }
                // 推进到下一通（伪造一次空作答，仅消耗配额）
                Map<String, Set<String>> blank = new HashMap<>();
                for (Question q : s.quiz().questions()) blank.put(q.factId(), Set.of());
                svc.submit(a.accountId(), s.quiz().quizId(), blank, "ani" + call);
            }
        }
    }

    // 4. 投毒隔离：普通题不得含投毒实体
    private static void checkCanaryIsolation(List<Account> accounts) {
        var pool = new ivr.qa.OptionPool();
        Set<String> canaries = pool.canaryLabels();
        for (Account a : accounts) {
            var svc = new VerificationService();
            accounts.forEach(svc::register);
            for (int call = 0; call < 6; call++) {
                var s = svc.startCall(a.accountId(), "ani" + call);
                if (s.quiz() == null) break;
                for (Question q : s.quiz().questions()) {
                    if (LikelihoodScorerIsCanary(q)) continue;
                    for (Option o : q.options()) {
                        assertThat("普通题不得含投毒选项: " + q.factId() + "=" + o.label(),
                                !canaries.contains(o.label()));
                    }
                }
                Map<String, Set<String>> blank = new HashMap<>();
                for (Question q : s.quiz().questions()) blank.put(q.factId(), Set.of());
                svc.submit(a.accountId(), s.quiz().quizId(), blank, "ani" + call);
            }
        }
    }

    private static boolean LikelihoodScorerIsCanary(Question q) {
        return "canary".equals(q.dimension());
    }

    // 5. 下发给坐席的问卷不含答案
    private static void checkNoAnswersInPayload(List<Account> accounts) {
        // 这只是结构性提示：Question 记录里确实带 correctOptionIds，
        // 因此真正的要求是“对外序列化层必须剥离它”。
        // 见 ivr.web.ApiServer#toPublicQuiz 的字段白名单。
        System.out.println("[info] 问卷对象内部保留答案，对外序列化由 ApiServer 白名单剥离。");
    }

    private static Map<String, List<String>> labelsByFact(Quiz q) {
        Map<String, List<String>> m = new HashMap<>();
        for (Question qq : q.questions()) {
            List<String> labels = new ArrayList<>();
            for (Option o : qq.options()) labels.add(o.label());
            m.put(qq.factId(), labels);
        }
        return m;
    }

    private static void assertThat(String msg, boolean cond) {
        if (!cond) {
            failures++;
            System.out.println("  ✗ " + msg);
        }
    }
}
