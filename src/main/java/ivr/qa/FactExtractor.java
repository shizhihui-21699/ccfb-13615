package ivr.qa;

import ivr.model.Account;
import ivr.model.Fact;
import ivr.model.FactClass;

import java.util.ArrayList;
import java.util.List;

/**
 * 从账户档案里抽取“可核验事实”，并给每条事实打上：
 *  - 泄露类别（决定它是不是在送分）
 *  - 被泄露/可推测概率 exposure
 *  - 真用户记忆噪声 userSlip
 *  - 敏感度 sensitivity
 *
 * <p>这里刻意把 PII/订单类事实也保留下来，但 exposure 给得很高，
 * 编排器因此几乎不会选它们。这样“不选泄露题”是算出来的，不是拍脑袋写死的。
 */
public final class FactExtractor {

    public List<Fact> extract(Account a) {
        List<Fact> facts = new ArrayList<>();

        // ---- 高泄露风险，仅作兜底（exposure 高 → 信息量≈0） ----
        facts.add(new Fact("birthday", FactClass.PII_DUMPED, "pii",
                "请报一下账户登记的出生年月日",
                a.birthday(), 0.96, 0.04, 1.0));
        facts.add(new Fact("addressCity", FactClass.PII_DUMPED, "pii",
                "请确认一下登记的常住城市",
                a.addressCity(), 0.92, 0.05, 0.8));
        facts.add(new Fact("idTail", FactClass.PII_DUMPED, "pii",
                "身份证后四位",
                a.idCardTail4(), 0.97, 0.06, 1.0));
        facts.add(new Fact("emailLocal", FactClass.PII_DUMPED, "pii",
                "登记邮箱",
                a.email(), 0.90, 0.08, 0.7));

        // ---- 订单类：电商泄露库常见 ----
        if (!a.recentOrders().isEmpty()) {
            Account.Order o = a.recentOrders().get(0);
            facts.add(new Fact("lastOrderMerchant", FactClass.ORDER_DUMPED, "order",
                    "最近一笔订单是在哪家商户下的",
                    o.merchant(), 0.78, 0.07, 0.5));
            facts.add(new Fact("lastOrderCity", FactClass.ORDER_DUMPED, "order",
                    "最近一笔订单的收货城市",
                    o.city(), 0.74, 0.08, 0.5));
        }

        // ---- 行为侧写：泄露库里通常不完整，且外人难猜 ----
        facts.add(new Fact("counterparty", FactClass.BEHAVIOR, "behavior",
                "您最常转账的那位联系人，昵称是",
                a.frequentCounterparty(), 0.18, 0.12, 0.6));
        facts.add(new Fact("device", FactClass.BEHAVIOR, "behavior",
                "您最常用的登录机型是",
                a.primaryDevice(), 0.22, 0.10, 0.4));
        facts.add(new Fact("favCategory", FactClass.BEHAVIOR, "behavior",
                "近一年您消费最集中的商户类别是",
                a.favoriteCategory(), 0.12, 0.20, 0.4));

        // ---- 聚合统计：库里几乎没有 ----
        facts.add(new Fact("topupsBucket", FactClass.DERIVED, "derived",
                "近半年该账户的充值笔数大致落在哪个区间",
                bucketOf(a.topupsLast6Months()), 0.04, 0.22, 0.3));

        // ---- 更多不易泄露的可核验事实（保证换题时有足够备选） ----
        if (a.recentOrders().size() >= 2) {
            Account.Order second = a.recentOrders().get(1);
            facts.add(new Fact("secondOrderMerchant", FactClass.BEHAVIOR, "behavior",
                    "您上一笔（不是最近一笔）订单是在哪家商户",
                    second.merchant(), 0.15, 0.22, 0.5));
        }
        facts.add(new Fact("usualChannel", FactClass.BEHAVIOR, "behavior",
                "您平时主要通过哪种方式使用本账户",
                a.usualChannel(), 0.20, 0.15, 0.3));
        facts.add(new Fact("orderAmountBand", FactClass.DERIVED, "derived",
                "您最近一笔订单的金额大致在哪个区间",
                amountBand(a.recentOrders().isEmpty() ? 0 : a.recentOrders().get(0).amountCents()),
                0.55, 0.25, 0.3));
        facts.add(new Fact("merchantDiversity", FactClass.DERIVED, "derived",
                "您近一年在本平台用过的商户，大致有几家",
                merchantCountBand(a.merchantsUsed().size()), 0.06, 0.25, 0.3));

        // ---- 约定暗语：与泄露数据完全无关 ----
        facts.add(new Fact("coSetSecret", FactClass.CO_SET_SECRET, "secret",
                "请说出您上次核验时和我们约定的安全暗语",
                a.coSetSecret(), 0.02, 0.10, 0.9));

        return facts;
    }

    /** 把连续量离散成区间，降低“记不清精确值”造成的误伤。 */
    public static String bucketOf(int n) {
        if (n <= 0) return "0 笔";
        if (n <= 2) return "1-2 笔";
        if (n <= 5) return "3-5 笔";
        if (n <= 10) return "6-10 笔";
        return "10 笔以上";
    }

    public static String amountBand(int cents) {
        int yuan = cents / 100;
        if (yuan < 50) return "50 元以下";
        if (yuan < 200) return "50-200 元";
        if (yuan < 500) return "200-500 元";
        if (yuan < 1000) return "500-1000 元";
        return "1000 元以上";
    }

    public static String merchantCountBand(int n) {
        if (n <= 1) return "1 家";
        if (n <= 3) return "2-3 家";
        if (n <= 6) return "4-6 家";
        return "6 家以上";
    }
}
