package ivr.data;

import ivr.model.Account;

import java.util.List;
import java.util.Set;

/** 模拟账户库。刻意混合“高泄露风险”和“低泄露风险”的账户。 */
public final class SeedData {

    public static List<Account> accounts() {
        return List.of(
                new Account("A1001", "林一舟", "138****6721", "1990-03-11", "杭州",
                        "4412", "yizhou.lin@mail.example", "蓝色小鲸鱼",
                        List.of(
                                new Account.Order("O-88213", 12800, "蓝湾咖啡", "杭州", "2026-11-02"),
                                new Account.Order("O-87110", 4599, "驿路便利店", "杭州", "2026-10-19")),
                        "阿满", "iPhone 13", "餐饮",
                        7, Set.of("蓝湾咖啡", "驿路便利店", "南风洗衣"), "6721", "手机 App"),

                new Account("A1002", "周敏", "139****3345", "1984-11-27", "成都",
                        "9021", "zhoumin84@mail.example", "熊猫与竹林",
                        List.of(
                                new Account.Order("O-90131", 23800, "云杉健身", "成都", "2026-11-10")),
                        "老周", "小米 14", "运动户外",
                        2, Set.of("云杉健身", "北纬药房"), "3345", "微信小程序"),

                new Account("A1003", "陈嘉禾", "151****9082", "1996-06-04", "厦门",
                        "1177", "jiahe.chen@mail.example", "海风咸咸的",
                        List.of(
                                new Account.Order("O-91022", 6900, "拾光影院", "厦门", "2026-11-14"),
                                new Account.Order("O-90551", 31500, "长风车行", "厦门", "2026-09-30")),
                        "青柠", "iPhone 15", "休闲娱乐",
                        12, Set.of("拾光影院", "长风车行", "老码头面馆"), "9082", "手机 App"),

                new Account("A1004", "吴承泽", "186****4410", "1978-01-19", "青岛",
                        "6634", "wucz@mail.example", "山与海之间",
                        List.of(
                                new Account.Order("O-92345", 88800, "山丘露营", "青岛", "2026-11-08")),
                        "三石", "华为 Mate 60", "户外露营",
                        4, Set.of("山丘露营", "橙子便利"), "4410", "电话语音")
        );
    }
}
