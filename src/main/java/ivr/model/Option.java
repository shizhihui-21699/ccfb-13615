package ivr.model;

/** 选项。注意：选项只暴露标签，正确性由服务端持有，永不下发。 */
public record Option(String id, String label) {
}
