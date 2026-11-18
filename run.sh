#!/usr/bin/env bash
# 构建并运行。无需 Gradle/Maven，只要 JDK 21+。
set -euo pipefail
cd "$(dirname "$0")"

# 找一个可用的 JDK 21+（macOS Homebrew 路径优先，其次系统 java）
for cand in \
  /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home \
  "${JAVA_HOME:-}"; do
  if [ -n "$cand" ] && [ -x "$cand/bin/javac" ]; then
    export JAVA_HOME="$cand"
    break
  fi
done
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "$JAVA_HOME/bin/javac" ]; then
  echo "未找到 JDK 21+，请设置 JAVA_HOME" >&2
  exit 1
fi

mkdir -p out
"$JAVA_HOME/bin/javac" -encoding UTF-8 -d out $(find src/main/java -name '*.java')

case "${1:-all}" in
  test)   exec "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.verify.InvariantTest ;;
  sim)    exec "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.sim.ExperimentRunner "${2:-500}" ;;
  sweep)  exec "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.sim.ParamSweep "${2:-300}" ;;
  rebind) exec "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.sim.RebindTest "${2:-400}" ;;
  web)    exec "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.web.ApiServer "${2:-8080}" ;;
  all)
    "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.verify.InvariantTest
    echo
    "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.sim.ExperimentRunner 500
    echo
    "$JAVA_HOME/bin/java" -Dfile.encoding=UTF-8 -cp out ivr.sim.RebindTest 400
    ;;
  *) echo "用法: $0 [all|test|sim N|sweep N|rebind N|web PORT]" >&2; exit 1 ;;
esac
