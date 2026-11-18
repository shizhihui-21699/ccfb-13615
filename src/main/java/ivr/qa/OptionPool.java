package ivr.qa;

import ivr.model.Option;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * 全局诱饵池 + 确定性选项生成。
 *
 * <p>两条硬规则：
 * <ol>
 *   <li><b>诱饵只能来自全局池，绝不能来自该用户的其它事实。</b>
 *       否则 A 题的错选项就是 B 题的正确答案 → 跨题泄露。</li>
 *   <li><b>同一 (账户, 维度, epoch) 的选项集合必须逐字节稳定。</b>
 *       若每次来电重洗，攻击者多次来电各提交一次、对选项做交集，
 *       就能把正确答案夹出来。</li>
 * </ol>
 */
public final class OptionPool {

    private static final String[] MERCHANT_POOL = {
            "蓝湾咖啡", "启点书店", "云杉健身", "驿路便利店", "青禾花艺",
            "老码头面馆", "星野烘焙", "拾光影院", "南风洗衣", "格物文具",
            "陆记粥铺", "北纬药房", "橙子便利", "慢时茶馆", "九格火锅",
            "山丘露营", "白鹭照相馆", "一叶书店", "长风车行", "沐光理发",
    };

    private static final String[] CITY_POOL = {
            "杭州", "苏州", "成都", "青岛", "长沙", "宁波", "合肥", "厦门",
            "郑州", "昆明", "无锡", "福州", "济南", "南昌", "贵阳", "太原",
    };

    private static final String[] DEVICE_POOL = {
            "iPhone 13", "iPhone 15", "Pixel 8", "小米 14", "Redmi Note 12",
            "华为 Mate 60", "OPPO Find X6", "vivo X90", "三星 S23", "荣耀 90",
    };

    private static final String[] NICKNAME_POOL = {
            "阿满", "小柯", "老周", "枝枝", "大鹏", "米粒", "阿哲", "团团",
            "青柠", "老徐", "柚子", "三石", "阿棠", "小满", "禾禾",
    };

    private static final String[] BUCKET_POOL = {
            "0 笔", "1-2 笔", "3-5 笔", "6-10 笔", "10 笔以上",
    };

    /** 投毒实体：只存在于我们“故意放出去”的假泄露库里，真用户从未见过。 */
    private static final String[] CANARY_MERCHANTS = {
            "赫兰迪斯百货", "维洛奇数码", "穹顶仓买", "斐瑟珠宝", "帛黎生鲜",
    };
    private static final String[] CANARY_CITIES = {
            "峪川", "柏陵", "澜尾",
    };

    public static final String NONE_OF_THESE = "以上都没有";

    private final Map<String, List<String>> pools = new HashMap<>();

    public OptionPool() {
        pools.put("merchant", List.of(MERCHANT_POOL));
        pools.put("city", List.of(CITY_POOL));
        pools.put("device", List.of(DEVICE_POOL));
        pools.put("nickname", List.of(NICKNAME_POOL));
        pools.put("bucket", List.of(BUCKET_POOL));
        pools.put("canary_merchant", List.of(CANARY_MERCHANTS));
        pools.put("canary_city", List.of(CANARY_CITIES));
    }

    /**
     * 稳定选项集合：正确标签 + k 个诱饵，顺序也确定。
     *
     * @param seedKey      形如 "acct|dimension|epoch"
     * @param forbiddenForUser 该用户所有“属于其某道题正确答案”的标签；
     *                     诱饵必须避开它们，否则就成了跨题泄露。
     */
    public List<Option> buildStableOptions(String seedKey, List<String> correctLabels,
                                           String poolName, int kDecoys, boolean includeCanary,
                                           Set<String> forbiddenForUser) {
        List<String> pool = new ArrayList<>(pools.getOrDefault(poolName, List.of()));
        pool.removeAll(correctLabels);
        // 关键：排除该用户所有其它事实的答案。否则 A 题的错选项可能正是 B 题的答案，
        // 攻击者用排除法即可跨题拼出信息。
        pool.removeAll(forbiddenForUser);
        pool.removeAll(usedMerchantLabels(forbiddenForUser));

        Random rnd = new Random(seedKey.hashCode() * 31L + poolName.hashCode());

        // bucket 题的正确选项本来就来自池中，诱饵就是其余区间，无需再洗。
        Collections.shuffle(pool, rnd);

        Set<String> labels = new LinkedHashSet<>(correctLabels);
        for (String d : pool) {
            if (labels.size() >= correctLabels.size() + kDecoys) break;
            labels.add(d);
        }

        List<String> ordered = new ArrayList<>(labels);
        Collections.shuffle(ordered, new Random(seedKey.hashCode() + 17L));

        List<Option> opts = new ArrayList<>();
        for (int i = 0; i < ordered.size(); i++) {
            opts.add(new Option(seedKey + "#o" + i, ordered.get(i)));
        }
        return opts;
    }

    /**
     * 商户池与“用户用过的商户”是同一语义空间。
     * 若用户常用的商户出现在普通题的诱饵里，会同时泄露“他常用哪家”。
     * 这里把它们一并从诱饵中剔除——投毒题例外（它本来就要展示真实商户）。
     */
    private Set<String> usedMerchantLabels(Set<String> forbidden) {
        return forbidden; // 调用方已把商户名放进 forbidden，语义上统一处理
    }

    public List<Option> buildStableOptions(String seedKey, List<String> correctLabels,
                                           String poolName, int kDecoys, boolean includeCanary) {
        return buildStableOptions(seedKey, correctLabels, poolName, kDecoys, includeCanary, Set.of());
    }

    /**
     * 投毒题专用：真实用过的商户 + 若干投毒商户 + “以上都没有”。
     * 固定混入 2 个投毒项和一个“都没有”兜底，避免真用户被迫瞎选。
     */
    public List<Option> buildCanaryQuestion(String seedKey, List<String> usedMerchants,
                                            boolean includeNone) {
        Random rnd = new Random(seedKey.hashCode());
        List<String> canaries = new ArrayList<>(List.of(CANARY_MERCHANTS));
        Collections.shuffle(canaries, rnd);

        Set<String> labels = new LinkedHashSet<>();
        labels.addAll(usedMerchants);
        labels.addAll(canaries.subList(0, 2));
        if (includeNone) labels.add(NONE_OF_THESE);

        List<String> ordered = new ArrayList<>(labels);
        Collections.shuffle(ordered, new Random(seedKey.hashCode() + 5L));

        List<Option> opts = new ArrayList<>();
        for (int i = 0; i < ordered.size(); i++) {
            opts.add(new Option(seedKey + "#o" + i, ordered.get(i)));
        }
        return opts;
    }

    public Set<String> canaryLabels() {
        Set<String> all = new LinkedHashSet<>();
        all.addAll(List.of(CANARY_MERCHANTS));
        all.addAll(List.of(CANARY_CITIES));
        return all;
    }

    public static Map<String, String> index(List<Option> options) {
        Map<String, String> m = new HashMap<>();
        for (Option o : options) m.put(o.id(), o.label());
        return m;
    }
}
