package ivr.sim;

import ivr.model.Option;
import ivr.model.Question;

import java.text.Normalizer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * 攻击者作答策略。
 *
 * <p><b>重要：这里刻意不给攻击者任何它拿不到的信息。</b>
 * 因为系统是“整批盲答、只回一个总判定”，攻击者从一次失败里
 * 只学到“至少有一题错了”，学不到是哪一题。任何按题排除的模型都是作弊，
 * 会把系统的安全性低估成假象。
 *
 * <p>因此真实策略只有：
 * <ul>
 *   <li>{@code BLIND_GUESS}：无库，纯随机。</li>
 *   <li>{@code DUMP_ONLY}：库里有就照念，没有就随机。</li>
 *   <li>{@code ADAPTIVE}：知道选项集稳定，于是<b>跨次固定选择</b>
 *       （不再随机抖动），企图用“多次同一批答案”撞中——这是我们最该测的。</li>
 *   <li>{@code DECLINE_STRATEGY}：只答有把握的一题、其余拒答，
 *       想利用“拒答不扣分”蒙混。</li>
 *   <li>{@code CANARY_EATER}：买了投毒库照念。</li>
 * </ul>
 */
public final class Attacker {

    public enum Strategy { BLIND_GUESS, DUMP_ONLY, ADAPTIVE, DECLINE_STRATEGY, CANARY_EATER }

    private final Strategy strategy;
    private final AttackerKnowledge knowledge;
    private final Random rnd;
    /** ADAPTIVE：factId -> 固定下来的选项 id，跨次不变。 */
    private final Map<String, String> pinnedChoice = new HashMap<>();

    public Attacker(Strategy strategy, AttackerKnowledge knowledge, long seed) {
        this.strategy = strategy;
        this.knowledge = knowledge;
        this.rnd = new Random(seed);
    }

    public Map<String, Set<String>> answer(List<Question> questions) {
        Map<String, Set<String>> out = new HashMap<>();
        for (Question q : questions) out.put(q.factId(), answerOne(q));
        return out;
    }

    private Set<String> answerOne(Question q) {
        String factId = q.factId();

        if ("canary".equals(q.dimension())) return answerCanary(q);

        // 拒答型攻击者：只回答库里有答案的题，其余一律拒答。
        if (strategy == Strategy.DECLINE_STRATEGY) {
            String known = knowledge.answerFor(factId);
            if (known != null) {
                for (Option o : q.options()) {
                    if (norm(o.label()).equals(norm(known))) return Set.of(o.id());
                }
            }
            return Set.of(); // 拒答
        }

        if (q.isFreeText()) {
            String k = knowledge.answerFor(factId);
            return Set.of(k != null ? k : "不知道" + rnd.nextInt(3));
        }

        // 照库念。
        if (strategy != Strategy.BLIND_GUESS) {
            String known = knowledge.answerFor(factId);
            if (known != null) {
                for (Option o : q.options()) {
                    if (norm(o.label()).equals(norm(known))) return Set.of(o.id());
                }
            }
        }

        // ADAPTIVE：利用“选项集稳定”，第一次随机选定后就锁死，反复提交同一答案。
        // 这在系统若保留了逐题反馈时会非常致命；本系统只回总判定，故收益≈0。
        if (strategy == Strategy.ADAPTIVE) {
            String pinned = pinnedChoice.get(factId);
            if (pinned != null && q.options().stream().anyMatch(o -> o.id().equals(pinned))) {
                return Set.of(pinned);
            }
            String pick = q.options().get(rnd.nextInt(q.options().size())).id();
            pinnedChoice.put(factId, pick);
            return Set.of(pick);
        }

        if (q.options().isEmpty()) return Set.of("?");
        return Set.of(q.options().get(rnd.nextInt(q.options().size())).id());
    }

    private Set<String> answerCanary(Question q) {
        if (strategy == Strategy.CANARY_EATER && knowledge.hasCanaryDump()) {
            for (Option o : q.options()) {
                if (isCanaryLabel(o.label())) return Set.of(o.id());
            }
        }
        for (Option o : q.options()) {
            if (o.label().equals("以上都没有")) return Set.of(o.id());
        }
        return Set.of(q.options().get(0).id());
    }

    private static boolean isCanaryLabel(String s) {
        return s.startsWith("赫兰") || s.startsWith("维洛") || s.startsWith("穹顶")
                || s.startsWith("斐瑟") || s.startsWith("帛黎");
    }

    /**
     * 保留接口但<b>故意什么都不学</b>。
     * 整批判定下，一次失败只意味着“至少一题错”，不构成逐题信息。
     * 若这里去做按题排除，等于假设系统泄露了逐题结果——那是对手的胜利条件，不是我们的。
     */
    public void observeFailure(List<Question> questions, Map<String, Set<String>> lastAnswer) {
        // no-op：这正是防御生效的直接体现。
    }

    private static String norm(String s) {
        return Normalizer.normalize(s, Normalizer.Form.NFKC).trim().toLowerCase();
    }
}
