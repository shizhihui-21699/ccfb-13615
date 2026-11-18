package ivr.model;

import java.util.List;

/** 账户原始档案 + 行为数据。真实系统里这些来自 CRM/订单库/设备指纹库。 */
public record Account(
        String accountId,
        String displayName,
        String phoneMasked,
        String birthday,          // 1990-03-11
        String addressCity,
        String idCardTail4,
        String email,
        String coSetSecret,       // 开户/上次核验时约定的暗语，与泄露数据无关
        List<Order> recentOrders,
        String frequentCounterparty,  // 最常转账对象的昵称
        String primaryDevice,         // 常用机型
        String favoriteCategory,      // 近一年偏好商户类别
        int topupsLast6Months,        // 近半年充值笔数
        java.util.Set<String> merchantsUsed,   // 用过的商户名
        String registeredAniTail,             // 登记来电号码后四位（用于 ANI 关联）
        String usualChannel) {                // 主要使用渠道：App / 小程序 / 电话 / 网页

    public record Order(String orderId, int amountCents, String merchant, String city, String date) {
    }
}
