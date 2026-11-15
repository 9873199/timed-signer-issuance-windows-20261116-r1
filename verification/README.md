在冻结后未改源码的replay-source运行。Python3.14，依赖版本见dependency-lock.stdout.log。设置PYTHONPATH为最终源码src和仓库根目录，执行 python -m pytest -q tests，340过；独立用例为 verification/acceptance-r1/test_contract.py，27过。真实HMAC签名的固定签发时刻由测试TimestampSigner子类提供，读取时钟注入且计次；并发验证使用两个独立迁移器和同步屏障。录屏的demo.py是单独评审辅助，运行真实冻结库。完整解释器、命令、日志及Hash随材料提供。

冻结产物提交：https://github.com/9873199/timed-signer-issuance-windows-20261116-r1/commit/3abc5b3775f3e8b6ccef6a1e988455b5cd940cdf
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
