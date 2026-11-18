package ivr.risk;

import ivr.model.AccountState;
import ivr.model.Question;
import ivr.model.Quiz;

/**
 * 暴露账本。
 *
 * <p>关键约束：<b>同一事实在同一个 epoch 内只计一次满额信息</b>。
 * 如果每来一次电都把“生日”重新问一遍，攻击者就能反复朝同一题撒网；
 * 而现实是，一旦某题被问过，它的选项池和问法就已经被对方掌握。
 * 所以再次问同一题应当接近零成本，但也接近零收益——在编排层被降权。
 */
public final class ExposureLedger {

    public void commit(AccountState st, Quiz quiz) {
        for (Question q : quiz.questions()) {
            String k = key(st, q.factId());
            double prev = st.exposedBits().getOrDefault(k, 0.0);
            // 第二次起只按 25% 计，避免重复问同一题反复扣预算，但仍有一点成本。
            double add = prev == 0 ? q.bitCost() : q.bitCost() * 0.25;
            st.exposedBits().put(k, prev + add);
        }
    }

    public boolean isBurned(AccountState st, String factId) {
        return st.dimensionBurned().getOrDefault(factId, false);
    }

    public void markBurned(AccountState st, String factId) {
        st.dimensionBurned().put(factId, true);
    }

    private String key(AccountState st, String factId) {
        return st.epoch() + "|" + factId;
    }
}
