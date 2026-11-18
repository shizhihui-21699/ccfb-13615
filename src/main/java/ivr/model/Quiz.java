package ivr.model;

import java.util.List;

/** 坐席看到的一份问卷（一次性、盲答、整批提交）。 */
public record Quiz(
        String quizId,
        String accountId,
        long issuedAtMillis,
        List<Question> questions,
        /** 该问卷是否为“诱饵题组”（只用于给攻击者定性，不产生额外信息）。 */
        boolean canaryBatch) {
}
