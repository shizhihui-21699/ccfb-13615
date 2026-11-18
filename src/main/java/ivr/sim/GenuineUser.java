package ivr.sim;

import ivr.model.Account;
import ivr.model.Option;
import ivr.model.Question;
import ivr.model.Quiz;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * 真用户模拟：绝大多数题答对，但有一定概率记错/听错（尤其模糊类）。
 * 用于衡量“误伤率”——这是需求里“不刁难真用户”的量化指标。
 */
public final class GenuineUser {

    private final Random rnd;
    /** 记忆噪声放大倍数。1.0=标称；>1 用于压测“真用户更糊涂”的悲观情形。 */
    private final double slipAmplifier;

    public GenuineUser(long seed) {
        this(seed, 1.0);
    }

    public GenuineUser(long seed, double slipAmplifier) {
        this.rnd = new Random(seed);
        this.slipAmplifier = slipAmplifier;
    }

    public Map<String, Set<String>> answer(Quiz quiz) {
        Map<String, Set<String>> out = new HashMap<>();
        for (Question q : quiz.questions()) {
            out.put(q.factId(), answerOne(q));
        }
        return out;
    }

    private Set<String> answerOne(Question q) {
        // 真用户的真实行为：没把握就拒答（空集），而不是硬猜。
        // 这既符合“不刁难用户”的产品要求，也让系统能区分“不确定”与“答错”。
        boolean slip = rnd.nextDouble() < effectiveSlip(q);

        if (q.isFreeText()) {
            String correct = q.correctOptionIds().get(0);
            if (!slip) return Set.of(correct);
            return Set.of(); // 拒答
        }

        if ("canary".equals(q.dimension())) {
            java.util.List<Option> own = q.options().stream()
                    .filter(o -> q.correctOptionIds().contains(o.id())).toList();
            if (!own.isEmpty() && !slip) {
                return Set.of(own.get(rnd.nextInt(own.size())).id());
            }
            return q.options().stream()
                    .filter(o -> o.label().equals("以上都没有"))
                    .map(Option::id).findFirst()
                    .map(Set::of).orElse(Set.of(q.options().get(0).id()));
        }

        if (!slip) {
            return Set.copyOf(q.correctOptionIds());
        }
        // 没把握：少数人会硬猜（给出错答案），多数直接拒答。
        if (rnd.nextDouble() < 0.35) {
            var wrong = q.options().stream()
                    .filter(o -> !q.correctOptionIds().contains(o.id())).toList();
            if (!wrong.isEmpty()) return Set.of(wrong.get(rnd.nextInt(wrong.size())).id());
        }
        return Set.of(); // 拒答
    }

    /** 敏感度越高，用户越紧张越容易答错一点点；但整体有上限。 */
    private double effectiveSlip(Question q) {
        return Math.min(0.45, q.userSlipProb() * (1.0 + 0.3 * q.sensitivity()) * slipAmplifier);
    }
}
