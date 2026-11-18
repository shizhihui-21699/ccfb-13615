package ivr.sim;

import ivr.model.Account;

import java.util.HashMap;
import java.util.Map;

/**
 * 攻击者知识库，代表“从泄露数据里拿到的东西”。
 *
 * <p>真实世界的数据边界：
 * <ul>
 *   <li>PII（生日/住址/证件/邮箱）几乎必在库里；</li>
 *   <li>订单明细在电商泄露里常见；</li>
 *   <li>行为侧写（常用设备、最常转账对象、消费偏好）通常拿不到；</li>
 *   <li>投毒数据取决于攻击者是否买到了我们放出去的那份。</li>
 * </ul>
 */
public final class AttackerKnowledge {

    public enum Template { NONE, PII, PII_ORDERS, PII_ORDERS_CANARY, FULL }

    private final Map<String, String> known = new HashMap<>();
    private boolean hasCanaryDump;

    public static AttackerKnowledge of(Template t, Account a) {
        AttackerKnowledge k = new AttackerKnowledge();
        if (t == Template.NONE) return k;

        k.known.put("birthday", a.birthday());
        k.known.put("addressCity", a.addressCity());
        k.known.put("idTail", a.idCardTail4());
        k.known.put("emailLocal", a.email());

        if (t != Template.PII && !a.recentOrders().isEmpty()) {
            var o = a.recentOrders().get(0);
            k.known.put("lastOrderMerchant", o.merchant());
            k.known.put("lastOrderCity", o.city());
        }
        if (t == Template.FULL) {
            k.known.put("counterparty", a.frequentCounterparty());
            k.known.put("device", a.primaryDevice());
            k.known.put("favCategory", a.favoriteCategory());
            k.known.put("topupsBucket", ivr.qa.FactExtractor.bucketOf(a.topupsLast6Months()));
            k.known.put("usualChannel", a.usualChannel());
            k.known.put("orderAmountBand",
                    ivr.qa.FactExtractor.amountBand(
                            a.recentOrders().isEmpty() ? 0 : a.recentOrders().get(0).amountCents()));
            k.known.put("merchantDiversity",
                    ivr.qa.FactExtractor.merchantCountBand(a.merchantsUsed().size()));
            if (a.recentOrders().size() >= 2) {
                k.known.put("secondOrderMerchant", a.recentOrders().get(1).merchant());
            }
        }
        k.hasCanaryDump = (t == Template.PII_ORDERS_CANARY);
        return k;
    }

    public String answerFor(String factId) { return known.get(factId); }
    public boolean knows(String factId) { return known.containsKey(factId); }
    public boolean hasCanaryDump() { return hasCanaryDump; }
}
